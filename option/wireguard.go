package option

import (
	"net/netip"

	"github.com/sagernet/sing/common/json/badoption"
)

type WireGuardEndpointOptions struct {
	System       bool                             `json:"system,omitempty"`
	Name         string                           `json:"name,omitempty"`
	MTU          uint32                           `json:"mtu,omitempty"`
	Address      badoption.Listable[netip.Prefix] `json:"address"`
	PrivateKey   string                           `json:"private_key"`
	ListenPort   uint16                           `json:"listen_port,omitempty"`
	Peers        []WireGuardPeer                  `json:"peers,omitempty"`
	UDPTimeout   badoption.Duration               `json:"udp_timeout,omitempty"`
	UDPMapping   UDPNATBehavior                   `json:"udp_mapping,omitempty"`
	UDPFiltering UDPNATBehavior                   `json:"udp_filtering,omitempty"`
	UDPNATMax    uint32                           `json:"udp_nat_max,omitempty"`
	Workers      int                              `json:"workers,omitempty"`
	OnDemand     bool                             `json:"on_demand,omitempty"`
	// AmneziaWG obfuscation parameters (jc/jmin/jmax/s1-s4/h1-h4/i1-i5 and the
	// AWG 3.x knobs). Embedded without a wrapper key so the fields live at the
	// endpoint root, matching the awg-quick/.conf layout. Effective only with
	// the `with_awg` build tag; otherwise setting any field is an explicit
	// error (see transport/wireguard/device_stub_awg.go).
	AmneziaWGOptions
	DialerOptions
}

type WireGuardPeer struct {
	Address                     string                       `json:"address,omitempty"`
	Port                        uint16                       `json:"port,omitempty"`
	PublicKey                   string                       `json:"public_key,omitempty"`
	PreSharedKey                string                       `json:"pre_shared_key,omitempty"`
	AllowedIPs                  LegacyListable[netip.Prefix] `json:"allowed_ips,omitempty"`
	PersistentKeepaliveInterval uint16                       `json:"persistent_keepalive_interval,omitempty"`
	Reserved                    []uint8                      `json:"reserved,omitempty"`
}
