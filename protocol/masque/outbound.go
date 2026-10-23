package masque

import (
	"context"
	"crypto/ecdsa"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/transport/device"
	"github.com/sagernet/sing-box/transport/masque"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MASQUEOutboundOptions](registry, C.TypeMASQUE, NewOutbound)
}

const defaultMTU uint32 = 1280

type Outbound struct {
	outbound.Adapter
	ctx       context.Context
	logger    log.ContextLogger
	dialer    N.Dialer
	dnsRouter adapter.DNSRouter
	profile   masque.Profile

	server     M.Socksaddr
	uri        string
	mtu        uint32
	prefixes   []netip.Prefix
	tlsConfig  *stdtls.Config
	quicConfig *quic.Config

	runMu  sync.Mutex
	sess   *session
	closed bool
}

type session struct {
	device   device.Device
	closer   io.Closer
	ipConn   masque.IpConn
	ctx      context.Context
	cancel   context.CancelFunc
	teardown sync.Once
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MASQUEOutboundOptions) (adapter.Outbound, error) {
	profile, err := masque.ParseProfile(options.Profile)
	if err != nil {
		return nil, err
	}

	uri := options.URI
	if uri == "" {
		uri = profile.DefaultURI
	}
	if uri == "" {
		return nil, E.New("masque: uri is required for the standard profile")
	}

	prefixes, err := parsePrefixes(options.IP, options.IPv6)
	if err != nil {
		return nil, err
	}

	var privKey *ecdsa.PrivateKey
	var pubKey *ecdsa.PublicKey
	if options.PrivateKey != "" {
		privKey, err = parseECPrivateKey(options.PrivateKey)
		if err != nil {
			return nil, E.Cause(err, "parse private_key")
		}
	}
	if options.PublicKey != "" {
		pubKey, err = parseECPublicKey(options.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "parse public_key")
		}
	}
	if profile.PinPublicKey && (privKey == nil || pubKey == nil) {
		return nil, E.New("masque: private_key and public_key are required for the cloudflare profile")
	}

	sni := ""
	if options.TLS != nil {
		sni = options.TLS.ServerName
	}
	if sni == "" {
		sni = profile.DefaultSNI
	}
	if sni == "" {
		sni = options.Server
	}

	insecure := options.TLS != nil && options.TLS.Insecure
	tlsConfig, err := masque.PrepareTLSConfig(profile, privKey, pubKey, sni, insecure)
	if err != nil {
		return nil, err
	}

	mtu := options.MTU
	if mtu == 0 {
		mtu = defaultMTU
	}

	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}

	quicConfig := &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 30 * time.Second,
	}

	networkList := options.NetworkList.Build()

	return &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeMASQUE, tag, networkList, options.DialerOptions),
		ctx:        ctx,
		logger:     logger,
		dialer:     outboundDialer,
		dnsRouter:  service.FromContext[adapter.DNSRouter](ctx),
		profile:    profile,
		server:     options.ServerOptions.Build(),
		uri:        uri,
		mtu:        mtu,
		prefixes:   prefixes,
		tlsConfig:  tlsConfig,
		quicConfig: quicConfig,
	}, nil
}

func (o *Outbound) ensureSession(ctx context.Context) (*session, error) {
	o.runMu.Lock()
	defer o.runMu.Unlock()
	if o.closed {
		return nil, E.New("masque: outbound closed")
	}
	if o.sess != nil {
		return o.sess, nil
	}

	// The userspace stack is built with transport/device, not
	// transport/wireguard.NewDevice. Upstream's wireguard.Device is a
	// WireGuard TUN: it routes stack-emitted packets to peers by their
	// AllowedIPs and its Read is never used by the tunnel pump. With no
	// WireGuard peer to route to, every packet becomes "unrouted", the stack
	// receives a synthesized ICMP host-unreachable and DialContext fails with
	// "go: connect: no route to host". transport/device is the upstream-native
	// stack for tunnel outbounds (MASQUE, OpenVPN, OpenConnect) and exposes the
	// two directions we actually need: SetPacketWriter (stack -> tunnel) and
	// WriteInboundBuffers (tunnel -> stack).
	o.logger.DebugContext(ctx, "masque: establishing h3 tunnel to ", o.server, " (sni=", o.tlsConfig.ServerName, ")")
	closer, ipConn, err := o.connectH3(ctx)
	if err != nil {
		o.logger.WarnContext(ctx, "masque: h3 tunnel to ", o.server, " failed: ", err)
		return nil, err
	}
	o.logger.InfoContext(ctx, "masque: h3 tunnel established to ", o.server)

	tunnelDevice, err := device.New(device.Options{
		Context: o.ctx,
		Logger:  o.logger,
		Name:    "masque",
		MTU:     o.mtu,
		Configuration: device.Configuration{
			MTU:     o.mtu,
			Address: o.prefixes,
		},
	})
	if err != nil {
		_ = ipConn.Close()
		_ = closer.Close()
		return nil, E.Cause(err, "create userspace stack")
	}
	tunnelDevice.SetPacketWriter(func(packetBuffers []*buf.Buffer) error {
		return writeToTunnel(tunnelDevice, ipConn, packetBuffers)
	})
	if err = tunnelDevice.Start(); err != nil {
		_ = tunnelDevice.Close()
		_ = ipConn.Close()
		_ = closer.Close()
		return nil, E.Cause(err, "start userspace stack")
	}

	sessCtx, cancel := context.WithCancel(o.ctx)
	s := &session{
		device: tunnelDevice,
		closer: closer,
		ipConn: ipConn,
		ctx:    sessCtx,
		cancel: cancel,
	}
	o.sess = s

	go o.pumpFromTunnel(s)

	return s, nil
}

func (o *Outbound) teardownSession(s *session) {
	s.teardown.Do(func() {
		s.cancel()
		if s.ipConn != nil {
			_ = s.ipConn.Close()
		}
		if s.closer != nil {
			_ = s.closer.Close()
		}
		if s.device != nil {
			_ = s.device.Close()
		}
		o.runMu.Lock()
		if o.sess == s {
			o.sess = nil
		}
		o.runMu.Unlock()
	})
}

func (o *Outbound) connectH3(ctx context.Context) (io.Closer, masque.IpConn, error) {
	udpConn, err := o.dialer.DialContext(ctx, N.NetworkUDP, o.server)
	if err != nil {
		return nil, nil, E.Cause(err, "dial udp")
	}
	o.logger.DebugContext(ctx, "masque: udp socket to ", o.server, " up, starting QUIC handshake")
	quicConn, err := quic.DialEarly(ctx, bufio.NewUnbindPacketConn(udpConn), udpConn.RemoteAddr(), o.tlsConfig, o.quicConfig)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, E.Cause(err, "dial quic")
	}
	tr, ipConn, err := masque.ConnectTunnelH3(ctx, o.profile, quicConn, o.uri)
	if err != nil {
		_ = udpConn.Close()
		return nil, nil, err
	}
	return &h3Closer{transport: tr, rawConn: udpConn}, ipConn, nil
}

// writeToTunnel is the stack -> tunnel half of the pump. transport/device
// invokes it from its own outbound queue goroutine with buffers it owns, so it
// releases them here; replies handed back by the transport (ICMP "packet too
// big") go straight back into the stack so it can lower its path MTU.
func writeToTunnel(tunnelDevice device.Device, ipConn masque.IpConn, packetBuffers []*buf.Buffer) error {
	defer buf.ReleaseMulti(packetBuffers)
	var replies []*buf.Buffer
	for _, packetBuffer := range packetBuffers {
		icmpReply, err := ipConn.WritePacket(packetBuffer.Bytes())
		if err != nil {
			buf.ReleaseMulti(replies)
			return err
		}
		if len(icmpReply) > 0 {
			replies = append(replies, buf.As(icmpReply))
		}
	}
	if len(replies) > 0 {
		_ = tunnelDevice.WriteInboundBuffers(replies)
	}
	return nil
}

func (o *Outbound) pumpFromTunnel(s *session) {
	defer o.teardownSession(s)
	for s.ctx.Err() == nil {
		packet, err := s.ipConn.ReadPacket()
		if err != nil {
			o.pumpFatal(s, "read from tunnel", err)
			return
		}
		if err = s.device.WriteInboundBuffers([]*buf.Buffer{buf.As(packet)}); err != nil {
			o.pumpFatal(s, "write to stack", err)
			return
		}
	}
}

func (o *Outbound) pumpFatal(s *session, op string, err error) {
	if s.ctx.Err() != nil {
		return
	}
	o.logger.Warn("masque: tunnel died: ", op, ": ", err)
}

func (o *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	s, err := o.ensureSession(ctx)
	if err != nil {
		return nil, err
	}
	if destination.IsDomain() {
		addresses, err := o.lookup(ctx, destination.Fqdn)
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, s.device, network, destination, addresses)
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return s.device.DialContext(ctx, network, destination)
}

func (o *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	s, err := o.ensureSession(ctx)
	if err != nil {
		return nil, err
	}
	if destination.IsDomain() {
		addresses, err := o.lookup(ctx, destination.Fqdn)
		if err != nil {
			return nil, err
		}
		packetConn, destinationAddress, err := N.ListenSerial(ctx, s.device, destination, addresses)
		if err != nil {
			return nil, err
		}
		if destinationAddress.IsValid() && destination != M.SocksaddrFrom(destinationAddress, destination.Port) {
			return bufio.NewNATPacketConn(bufio.NewPacketConn(packetConn), M.SocksaddrFrom(destinationAddress, destination.Port), destination), nil
		}
		return packetConn, nil
	}
	if !destination.Addr.IsValid() {
		return nil, E.New("invalid destination: ", destination)
	}
	return s.device.ListenPacket(ctx, destination)
}

func (o *Outbound) lookup(ctx context.Context, domain string) ([]netip.Addr, error) {
	if o.dnsRouter == nil {
		return nil, E.New("masque: no DNS router available to resolve ", domain)
	}
	return o.dnsRouter.Lookup(ctx, domain, adapter.DNSQueryOptions{})
}

func (o *Outbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage == adapter.StartStateInitialize {
		scope.Add(o.Close)
	}
	return nil
}

func (o *Outbound) Close() error {
	o.runMu.Lock()
	if o.closed {
		o.runMu.Unlock()
		return nil
	}
	o.closed = true
	s := o.sess
	o.sess = nil
	o.runMu.Unlock()
	if s != nil {
		o.teardownSession(s)
	}
	return nil
}

type h3Closer struct {
	transport io.Closer
	rawConn   net.Conn
}

func (c *h3Closer) Close() error {
	if c.transport != nil {
		_ = c.transport.Close()
	}
	if c.rawConn != nil {
		_ = c.rawConn.Close()
	}
	return nil
}

func parsePrefixes(ip, ipv6 string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, 2)
	if ip != "" {
		if !strings.Contains(ip, "/") {
			ip += "/32"
		}
		prefix, err := netip.ParsePrefix(ip)
		if err != nil {
			return nil, E.Cause(err, "parse ip")
		}
		prefixes = append(prefixes, prefix)
	}
	if ipv6 != "" {
		if !strings.Contains(ipv6, "/") {
			ipv6 += "/128"
		}
		prefix, err := netip.ParsePrefix(ipv6)
		if err != nil {
			return nil, E.Cause(err, "parse ipv6")
		}
		prefixes = append(prefixes, prefix)
	}
	if len(prefixes) == 0 {
		return nil, E.New("masque: at least one of ip/ipv6 is required")
	}
	return prefixes, nil
}

func parseECPrivateKey(b64 string) (*ecdsa.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return x509.ParseECPrivateKey(der)
}

func parseECPublicKey(b64 string) (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, E.New("public_key is not an ECDSA key")
	}
	return ecPub, nil
}
