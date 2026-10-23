package autoreg

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	accountFileName = "warp-masque-account.json"
	outFileName     = "warp-wg.json"

	masqueServerName = "consumer-masque.cloudflareclient.com"
	masqueMTU        = 1280
)

var ErrRegisterFailed = errors.New("masque registration failed")

type masqueEndpoint struct {
	Tag    string
	Server string
	Port   uint16
}

var masqueEndpoints = []masqueEndpoint{
	{"warp-masque-1", "162.159.198.1", 443},
	{"warp-masque-2", "162.159.199.2", 443},
}

func accountPath(root string) string { return filepath.Join(root, accountFileName) }
func tmpPath(path string) string     { return path + ".tmp" }
func nowSecs() int64                 { return time.Now().Unix() }

func generateMasqueKeypair() (string, string, string, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate key: %w", err)
	}
	privDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return "", "", "", fmt.Errorf("marshal ec private key: %w", err)
	}
	privateB64 := base64.StdEncoding.EncodeToString(privDER)
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return "", "", "", fmt.Errorf("marshal pkix public key: %w", err)
	}
	publicSPKIB64 := base64.StdEncoding.EncodeToString(pubDER)
	point := elliptic.Marshal(elliptic.P256(), priv.PublicKey.X, priv.PublicKey.Y)
	publicSEC1B64 := base64.StdEncoding.EncodeToString(point)
	return privateB64, publicSPKIB64, publicSEC1B64, nil
}

func randomID() (string, error) {
	b := make([]byte, 11)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func newHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func registerMasque(privateKeySEC1, publicKeySPKI string) (map[string]any, error) {
	resp, err := doRegister(privateKeySEC1, publicKeySPKI)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRegisterFailed, err)
	}
	return resp, nil
}

func doRegister(privateKeySEC1, publicKeySPKI string) (map[string]any, error) {
	client := newHTTPClient()
	installID, err := randomID()
	if err != nil {
		return nil, fmt.Errorf("random install_id: %w", err)
	}
	fcmToken, err := randomID()
	if err != nil {
		return nil, fmt.Errorf("random fcm_token: %w", err)
	}
	postURL := "https://api.cloudflareclient.com/v0a4471/reg"
	postBody := map[string]any{
		"key":         privateKeySEC1,
		"install_id":  installID,
		"fcm_token":   fcmToken,
		"type":        "Android",
		"locale":      "en-US",
		"key_type":    "secp256r1",
		"tunnel_type": "masque",
	}
	postResp, err := doJSON(client, http.MethodPost, postURL, postBody, map[string]string{
		"CF-Client-Version": "a-6.35-4471",
	})
	if err != nil {
		return nil, fmt.Errorf("POST registration: %w", err)
	}
	id, _ := postResp["id"].(string)
	if id == "" {
		return nil, errors.New("POST response missing `id`")
	}
	token, _ := postResp["token"].(string)
	if token == "" {
		return nil, errors.New("POST response missing `token`")
	}
	patchURL := "https://api.cloudflareclient.com/v0a4471/reg/" + id
	patchBody := map[string]any{
		"key":         publicKeySPKI,
		"key_type":    "secp256r1",
		"tunnel_type": "masque",
	}
	patchResp, err := doJSON(client, http.MethodPatch, patchURL, patchBody, map[string]string{
		"CF-Client-Version": "a-6.35-4471",
		"Authorization":     "Bearer " + token,
	})
	if err != nil {
		return nil, fmt.Errorf("PATCH update: %w", err)
	}
	return patchResp, nil
}

func doJSON(client *http.Client, method, url string, body any, headers map[string]string) (map[string]any, error) {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, fmt.Errorf("encode body: %w", err)
		}
	}
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("User-Agent", "WARP for Android")
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s send: %w", method, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s failed [%d]: %s", method, resp.StatusCode, string(raw))
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("%s parse: %w", method, err)
	}
	return out, nil
}

func getPath(v map[string]any, path ...string) (any, bool) {
	var cur any = v
	for _, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = m[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func extractAddresses(resp map[string]any) (ip, ipv6 string, err error) {
	config, _ := getPath(resp, "config")
	cfgMap, _ := config.(map[string]any)
	if cfgMap == nil {
		return "", "", errors.New("missing config")
	}
	iface, _ := cfgMap["interface"].(map[string]any)
	if iface != nil {
		if addrs, ok := iface["addresses"].(map[string]any); ok {
			ip, _ = addrs["v4"].(string)
			ipv6, _ = addrs["v6"].(string)
		}
	}
	if ip == "" {
		ip, _ = cfgMap["ip"].(string)
	}
	if ipv6 == "" {
		ipv6, _ = cfgMap["ipv6"].(string)
	}
	if ip == "" {
		return "", "", errors.New("failed to parse IPv4 address")
	}
	if ipv6 == "" {
		return "", "", errors.New("failed to parse IPv6 address")
	}
	return ip, ipv6, nil
}

func extractEndpointPubKey(resp map[string]any) (string, error) {
	peersAny, ok := getPath(resp, "config", "peers")
	if !ok {
		return "", errors.New("failed to extract config.peers[0].public_key")
	}
	peers, ok := peersAny.([]any)
	if !ok || len(peers) == 0 {
		return "", errors.New("failed to extract config.peers[0].public_key")
	}
	peer, ok := peers[0].(map[string]any)
	if !ok {
		return "", errors.New("failed to extract config.peers[0].public_key")
	}
	raw, _ := peer["public_key"].(string)
	if raw == "" {
		return "", errors.New("failed to extract config.peers[0].public_key")
	}
	var sb strings.Builder
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "-----") {
			continue
		}
		sb.WriteString(line)
	}
	cleaned := sb.String()
	if cleaned == "" {
		return "", errors.New("peers[0].public_key is empty after stripping PEM")
	}
	return cleaned, nil
}

func extractPrivateKey(resp map[string]any) (string, bool) {
	s, ok := resp["private_key"].(string)
	if !ok || s == "" {
		return "", false
	}
	return s, true
}

func buildMasqueOutbound(tag, server string, port uint16, privateKey, publicKey, ip, ipv6 string) map[string]any {
	return map[string]any{
		"type":        "masque",
		"tag":         tag,
		"server":      server,
		"server_port": port,
		"tls": map[string]any{
			"enabled":     true,
			"server_name": masqueServerName,
		},
		"private_key": privateKey,
		"public_key":  publicKey,
		"ip":          ip,
		"ipv6":        ipv6,
		"mtu":         masqueMTU,
	}
}

func generateSingboxOutbounds(privateKey, publicKey, ip, ipv6 string) []any {
	out := make([]any, 0, len(masqueEndpoints))
	for _, ep := range masqueEndpoints {
		out = append(out, buildMasqueOutbound(ep.Tag, ep.Server, ep.Port, privateKey, publicKey, ip, ipv6))
	}
	return out
}

type accountState int

const (
	accountValid  accountState = iota
	accountAbsent
	accountBroken
)

func loadAccount(root string) (map[string]any, accountState) {
	path := accountPath(root)
	text, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, accountAbsent
		}
		slog.Warn("masque: read account failed", "path", path, "err", err)
		return nil, accountAbsent
	}
	var v map[string]any
	if err := json.Unmarshal(text, &v); err != nil || v == nil {
		slog.Warn("masque: account broken (parse)", "path", path, "err", err)
		return nil, accountBroken
	}
	_, hasPriv := extractPrivateKey(v)
	_, pubErr := extractEndpointPubKey(v)
	hasPub := pubErr == nil
	_, _, addrErr := extractAddresses(v)
	hasIP := addrErr == nil
	if !(hasPriv && hasPub && hasIP) {
		slog.Warn("masque: account missing key fields", "path", path, "priv", hasPriv, "pub", hasPub, "addr", hasIP)
		return nil, accountBroken
	}
	return v, accountValid
}

func backupBrokenAccount(root, reason string) {
	path := accountPath(root)
	if _, err := os.Stat(path); err != nil {
		return
	}
	bak := filepath.Join(root, fmt.Sprintf("%s.bak-%s-%d", accountFileName, reason, nowSecs()))
	if err := os.Rename(path, bak); err != nil {
		slog.Warn("masque: backup broken account failed", "from", path, "to", bak, "err", err)
		return
	}
	slog.Info("masque: backed up broken account", "to", bak)
}

func saveAccount(root string, resp map[string]any) error {
	path := accountPath(root)
	tmp := tmpPath(path)
	text, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize account: %w", err)
	}
	if err := os.WriteFile(tmp, text, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s -> %s: %w", tmp, path, err)
	}
	return nil
}

func mergeOutboundsInto(path string, outbounds []any) error {
	root := map[string]any{}
	text, err := os.ReadFile(path)
	if err == nil {
		if len(bytes.TrimSpace(text)) > 0 {
			if err := json.Unmarshal(text, &root); err != nil {
				return fmt.Errorf("parse %s: %w", path, err)
			}
			if root == nil {
				return fmt.Errorf("%s: top-level is not a JSON object; refusing to overwrite", path)
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read %s: %w", path, err)
	}
	root["outbounds"] = outbounds
	text, err = json.MarshalIndent(root, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize %s: %w", path, err)
	}
	if parent := filepath.Dir(path); parent != "" {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", parent, err)
		}
	}
	if err := os.WriteFile(path, text, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func Register(root string) (bool, string, error) {
	outDir := filepath.Join(root, "proxies")
	outPath := filepath.Join(outDir, outFileName)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return false, "", fmt.Errorf("mkdir: %w", err)
	}
	account, state := loadAccount(root)
	switch state {
	case accountValid:
		privateKey, ok := extractPrivateKey(account)
		if !ok {
			return false, "", errors.New("account file missing private_key (should not happen after validation)")
		}
		ip, ipv6, err := extractAddresses(account)
		if err != nil {
			return false, "", err
		}
		endpointPubKey, err := extractEndpointPubKey(account)
		if err != nil {
			return false, "", err
		}
		ipClean := strings.SplitN(ip, "/", 2)[0]
		ipv6Clean := strings.SplitN(ipv6, "/", 2)[0]
		outbounds := generateSingboxOutbounds(
			privateKey, endpointPubKey,
			ipClean+"/32", ipv6Clean+"/128",
		)
		if err := mergeOutboundsInto(outPath, outbounds); err != nil {
			return false, "", err
		}
		slog.Info("masque: reused existing account, regenerated outbounds", "path", outPath)
		return true, outPath, nil
	case accountBroken:
		slog.Warn("masque: existing account is broken, will re-register and overwrite", "path", accountPath(root))
	case accountAbsent:
		slog.Info("masque: no account file, registering new device")
	}
	privateKey, publicKeySPKI, _, err := generateMasqueKeypair()
	if err != nil {
		return false, "", fmt.Errorf("generate keypair: %w", err)
	}
	resp, err := registerMasque(privateKey, publicKeySPKI)
	if err != nil {
		return false, "", err
	}
	if _, ok := resp["private_key"]; !ok {
		resp["private_key"] = privateKey
	}
	if state == accountBroken {
		backupBrokenAccount(root, "missing-fields")
	}
	if err := saveAccount(root, resp); err != nil {
		return false, "", fmt.Errorf("save account: %w", err)
	}
	if _, err := extractEndpointPubKey(resp); err != nil {
		return false, "", fmt.Errorf("registered response missing peers[0].public_key: %w", err)
	}
	if _, _, err := extractAddresses(resp); err != nil {
		return false, "", fmt.Errorf("registered response missing addresses: %w", err)
	}
	slog.Info("masque: account saved", "path", accountPath(root))
	ip, ipv6, err := extractAddresses(resp)
	if err != nil {
		return false, "", err
	}
	endpointPubKey, err := extractEndpointPubKey(resp)
	if err != nil {
		return false, "", err
	}
	ipClean := strings.SplitN(ip, "/", 2)[0]
	ipv6Clean := strings.SplitN(ipv6, "/", 2)[0]
	outbounds := generateSingboxOutbounds(
		privateKey, endpointPubKey,
		ipClean+"/32", ipv6Clean+"/128",
	)
	if err := mergeOutboundsInto(outPath, outbounds); err != nil {
		return false, "", err
	}
	slog.Info("masque: wrote outbounds", "path", outPath)
	return false, outPath, nil
}