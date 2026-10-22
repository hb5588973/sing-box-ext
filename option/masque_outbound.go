package option

type MASQUEOutboundOptions struct {
	ServerOptions
	Profile    string              `json:"profile,omitempty"`
	PrivateKey string              `json:"private_key,omitempty"`
	PublicKey  string              `json:"public_key,omitempty"`
	IP         string              `json:"ip,omitempty"`
	IPv6       string              `json:"ipv6,omitempty"`
	URI        string              `json:"uri,omitempty"`
	TLS        *OutboundTLSOptions `json:"tls,omitempty"`
	MTU        uint32              `json:"mtu,omitempty"`
	DialerOptions
	NetworkList NetworkList `json:"network,omitempty"`
}