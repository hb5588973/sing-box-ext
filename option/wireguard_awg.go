package option

import (
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/schema"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

// AWGRange is an AmneziaWG "number or inclusive range" parameter: a single
// uint32 or a "min-max" string (min ≤ max). AWG 2.0 introduced the form for
// the magic headers H1..H4 (e.g. "43613244-384550127"); AWG 3.x uses it for
// every ranged knob — content padding addition and the timing overrides. It
// holds the canonical spec string the device layer understands (UintRange
// .FromString in the vendored wireguard-go): "N" for a single value, "N-M" for
// a range, "" for unset.
//
// The underlying type is string so AmneziaWGOptions stays comparable (IsSet
// relies on o != AmneziaWGOptions{}) and the zero value means "not set".
type AWGRange string

// MagicHeader is one AmneziaWG magic-header parameter (H1..H4). It is the
// same "number or range" type as every other AWG range; the name is kept for
// readers coming from the AWG 2.0 documentation.
type MagicHeader = AWGRange

// UnmarshalJSON accepts a JSON number (the AWG 2.0 form: "h1": 1234567890) or
// a JSON string "N" / "N-M". The single value 0 (and "", "0") normalizes to
// unset, so a zero value never reaches the device.
func (r *AWGRange) UnmarshalJSON(data []byte) error {
	var spec string
	if len(data) > 0 && data[0] == '"' {
		err := json.Unmarshal(data, &spec)
		if err != nil {
			return err
		}
	} else {
		var value uint32
		err := json.Unmarshal(data, &value)
		if err != nil {
			return E.New("invalid range ", string(data), ": expected uint32 or \"min-max\" string")
		}
		spec = strconv.FormatUint(uint64(value), 10)
	}
	normalized, err := normalizeAWGRange(spec)
	if err != nil {
		return err
	}
	*r = normalized
	return nil
}

// MarshalJSON keeps type fidelity with the numeric fields AmneziaWG configs
// already use: a single value marshals back to a JSON number, only a range
// becomes a JSON string.
func (r AWGRange) MarshalJSON() ([]byte, error) {
	normalized, err := normalizeAWGRange(string(r))
	if err != nil {
		return nil, err
	}
	if normalized == "" {
		return []byte("0"), nil
	}
	if !strings.Contains(string(normalized), "-") {
		return []byte(normalized), nil
	}
	return json.Marshal(string(normalized))
}

// DescribeSchema maps AWGRange to its JSON schema: a uint32 number or a
// "N" / "N-M" string, mirroring UnmarshalJSON. Custom JSON types must describe
// themselves or `sing-box schema` aborts on the first field it meets.
func (r AWGRange) DescribeSchema(builder schema.Builder) (*schema.Node, error) {
	return builder.Define("AWGRange", func() (*schema.Node, error) {
		return schema.AnyOf(
			schema.UnsignedNode(32),
			&schema.Node{Type: "string", Pattern: awgRangePattern},
		), nil
	})
}

const awgRangePattern = `^\s*\d+\s*(-\s*\d+\s*)?$`

// Spec re-validates the value and returns the canonical IpcSet spec ("" when
// unset). The device layer calls it so options constructed in code (libbox,
// launcher — bypassing JSON) are still checked before IpcSet.
func (r AWGRange) Spec() (string, error) {
	normalized, err := normalizeAWGRange(string(r))
	return string(normalized), err
}

// IsRange reports whether the value is a genuine "min-max" span (min < max)
// rather than a single number or unset.
func (r AWGRange) IsRange() bool {
	normalized, err := normalizeAWGRange(string(r))
	return err == nil && strings.Contains(string(normalized), "-")
}

// normalizeAWGRange validates spec as "N" or "N-M" (both uint32, N ≤ M) and
// returns the canonical form: "" for unset/zero, "N" for a single value
// (including "N-N"), "N-M" for a range — mirroring UintRange.FromString in the
// vendored wireguard-go.
func normalizeAWGRange(spec string) (AWGRange, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", nil
	}
	parts := strings.Split(spec, "-")
	if len(parts) > 2 {
		return "", E.New("invalid range ", strconv.Quote(spec), ": expected uint32 or \"min-max\"")
	}
	start, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 32)
	if err != nil {
		return "", E.New("invalid range ", strconv.Quote(spec), ": parse ", strconv.Quote(parts[0]), ": ", err)
	}
	end := start
	if len(parts) == 2 {
		end, err = strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 32)
		if err != nil {
			return "", E.New("invalid range ", strconv.Quote(spec), ": parse ", strconv.Quote(parts[1]), ": ", err)
		}
	}
	if end < start {
		return "", E.New("invalid range ", strconv.Quote(spec), ": range start > end")
	}
	if end == 0 {
		return "", nil
	}
	if start == end {
		return AWGRange(strconv.FormatUint(start, 10)), nil
	}
	return AWGRange(strconv.FormatUint(start, 10) + "-" + strconv.FormatUint(end, 10)), nil
}

// AmneziaWGOptions carries the AmneziaWG obfuscation parameters that extend a
// plain WireGuard endpoint into an AmneziaWG client: the AWG 2.0 junk/header
// fields plus the AWG 3.x header protection, content padding, random trailers,
// cookie switch and timing overrides.
//
// The struct is always present in the option model so that configs parse
// identically with and without the `with_awg` build tag — the tag only gates
// whether these values are actually applied to the device (see
// transport/wireguard/device_awg.go vs device_stub_awg.go). Without the tag a
// config that sets any AWG field is rejected with an explicit
// "awg support not built" error rather than silently downgrading to plain
// WireGuard, which would defeat the obfuscation.
//
// Field semantics (AmneziaWG wire format, see the amneziawg-go IpcSet keys):
//   - Jc/Jmin/Jmax: junk packet count and min/max sizes sent before the
//     handshake.
//   - S1/S2: extra junk prepended to the init / response handshake messages.
//     S3/S4: the same for cookie-reply / transport messages (AWG 2.0).
//   - H1..H4: magic header values overriding the four WireGuard message types;
//     each is a single uint32 or an inclusive "min-max" range (AWG 2.0).
//   - I1..I5: AWG 2.0 "controlled packet sequence" (CPS) packets. These are
//     case-sensitive strings (UPPERCASE keywords like <b 0x...>, <c>, <t>,
//     <r N>) and the order matters; I1 is typically a real protocol snapshot
//     (e.g. a QUIC Initial).
//   - HeaderProtectionKey (AWG 3.0, server-side — must match the server): the
//     base64 32-byte key (`awg genkey`) of the header cipher that masks the
//     message type, receiver index and counter of every packet, keyed per
//     datagram by the first 12 bytes of its S1–S4 padding. Requires each of
//     S1–S4 ≥ 12.
//   - ContentPaddingAddition (AWG 3.0, client-side): "min-max" bytes of extra
//     padding inside the encrypted payload of every data packet, in place of
//     WireGuard's multiple-of-16 pad.
//   - RekeyAfterTime / RekeyTimeout / RejectAfterTime / KeepaliveTimeout /
//     MaxHandshakeAttempts (AWG 3.0, client-side): "min-max" overrides of the
//     WireGuard timing constants (seconds / attempts), re-picked at every use.
//   - RandomTrailers (AWG 3.1, client-side): append a random-length random tail
//     to every handshake message and (inside the payload) to data packets.
//   - DisableCookies (AWG 3.1, client-side): never send or demand cookie
//     replies, so a cookie exchange can't expose the WireGuard shape.
type AmneziaWGOptions struct {
	Jc   uint32      `json:"jc,omitempty"`
	Jmin uint32      `json:"jmin,omitempty"`
	Jmax uint32      `json:"jmax,omitempty"`
	S1   uint32      `json:"s1,omitempty"`
	S2   uint32      `json:"s2,omitempty"`
	S3   uint32      `json:"s3,omitempty"`
	S4   uint32      `json:"s4,omitempty"`
	H1   MagicHeader `json:"h1,omitempty"`
	H2   MagicHeader `json:"h2,omitempty"`
	H3   MagicHeader `json:"h3,omitempty"`
	H4   MagicHeader `json:"h4,omitempty"`
	I1   string      `json:"i1,omitempty"`
	I2   string      `json:"i2,omitempty"`
	I3   string      `json:"i3,omitempty"`
	I4   string      `json:"i4,omitempty"`
	I5   string      `json:"i5,omitempty"`

	// AmneziaWG 3.x
	HeaderProtectionKey    string   `json:"header_protection_key,omitempty"`
	ContentPaddingAddition AWGRange `json:"content_padding_addition,omitempty"`
	RekeyAfterTime         AWGRange `json:"rekey_after_time,omitempty"`
	RekeyTimeout           AWGRange `json:"rekey_timeout,omitempty"`
	RejectAfterTime        AWGRange `json:"reject_after_time,omitempty"`
	KeepaliveTimeout       AWGRange `json:"keepalive_timeout,omitempty"`
	MaxHandshakeAttempts   AWGRange `json:"max_handshake_attempts,omitempty"`
	RandomTrailers         bool     `json:"random_trailers,omitempty"`
	DisableCookies         bool     `json:"disable_cookies,omitempty"`
}

// IsSet reports whether any AmneziaWG obfuscation parameter has been
// configured. It is used by the device builder/stub to decide whether AWG
// handling is required for this endpoint.
func (o AmneziaWGOptions) IsSet() bool {
	return o != AmneziaWGOptions{}
}
