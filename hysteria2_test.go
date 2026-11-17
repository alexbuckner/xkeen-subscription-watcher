package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestHysteria2Userinfo(t *testing.T) {
	for _, tc := range []struct {
		name, userinfo, auth string
	}{
		{"userpass", "user:password:tail", "user:password:tail"},
		{"encoded_colon", "user%3Apassword", "user:password"},
		{"encoded_reserved_unicode", "user%3A%40%2B%25%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8C", "user:@+%пароль"},
		{"literal_plus", "user+name:pass+word", "user+name:pass+word"},
		{"encoded_percent_once", "%253A%2540%252B", "%3A%40%2B"},
		{"empty_password", "user:", "user:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, err := parseProxyURL("hysteria2://" + tc.userinfo + "@server.example")
			if err != nil {
				t.Fatal(err)
			}
			if got := p.(hysteria2Proxy).auth; got != tc.auth {
				t.Fatalf("auth = %q, want %q", got, tc.auth)
			}
		})
	}
}

func TestHysteria2AddressAndAlias(t *testing.T) {
	for _, tc := range []struct {
		uri, address string
		port         int
	}{
		{"hy2://auth@server.example", "server.example", 443},
		{"HYSTERIA2://auth@server.example:8443/", "server.example", 8443},
		{"hysteria2://auth@[2001:db8::1]", "2001:db8::1", 443},
		{"hy2://auth@[2001:db8::1]:8443/#label", "2001:db8::1", 8443},
		{"hysteria2://server.example", "server.example", 443},
	} {
		p, err := parseProxyURL(tc.uri)
		if err != nil {
			t.Fatalf("%s: %v", tc.uri, err)
		}
		got := p.(hysteria2Proxy)
		if got.address != tc.address || got.port != tc.port {
			t.Errorf("address/port = %s:%d, want %s:%d", got.address, got.port, tc.address, tc.port)
		}
	}
}

func TestHysteria2NativeOutbound(t *testing.T) {
	p, err := parseProxyURL("hy2://user:password@server.example:8443/?security=tls&sni=tls.example&alpn=h3%2Ctest&obfs=salamander&obfs-password=mask%2B%3A%40%25%D0%BF#name")
	if err != nil {
		t.Fatal(err)
	}
	got := generateOutbound(p, "hy2-test", "", "chain")
	want := map[string]any{
		"tag": "hy2-test", "protocol": "hysteria",
		"settings": map[string]any{"version": 2, "address": "server.example", "port": 8443},
		"streamSettings": map[string]any{
			"network": "hysteria", "security": "tls",
			"tlsSettings":      map[string]any{"serverName": "tls.example", "allowInsecure": false, "alpn": []string{"h3", "test"}},
			"hysteriaSettings": map[string]any{"version": 2, "auth": "user:password", "keepAlivePeriod": 5},
			"finalmask":        map[string]any{"udp": []any{map[string]any{"type": "salamander", "settings": map[string]any{"password": "mask+:@%п"}}}},
			"sockopt":          map[string]any{"dialerProxy": "chain"},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("outbound = %#v, want %#v", got, want)
	}
}

func TestHysteria2TLSVerification(t *testing.T) {
	for _, tc := range []struct {
		query    string
		insecure bool
	}{
		{"", false}, {"?insecure=0", false}, {"?insecure=1", true},
	} {
		p, err := parseProxyURL("hy2://auth@server.example" + tc.query)
		if err != nil {
			t.Fatal(err)
		}
		ss := generateOutbound(p, "test", "", "")["streamSettings"].(map[string]any)
		tls := ss["tlsSettings"].(map[string]any)
		if tls["allowInsecure"] != tc.insecure || tls["serverName"] != "server.example" {
			t.Fatalf("query %s: TLS = %#v", tc.query, tls)
		}
		if _, ok := tls["alpn"]; ok {
			t.Fatal("absent ALPN must preserve Xray's default")
		}
		if _, ok := ss["finalmask"]; ok {
			t.Fatal("absent obfs must not enable an obfuscator")
		}
	}
}

func TestHysteria2RejectsUnsupportedOrMalformed(t *testing.T) {
	for name, suffix := range map[string]string{
		"unsupported_obfs":      "?obfs=gecko&obfs-password=secret",
		"empty_obfs":            "?obfs=",
		"missing_obfs_password": "?obfs=salamander",
		"empty_obfs_password":   "?obfs=salamander&obfs-password=",
		"orphan_obfs_password":  "?obfs-password=secret",
		"duplicate":             "?sni=one&sni=two",
		"duplicate_encoded":     "?sni=one&%73ni=two",
		"duplicate_identical":   "?insecure=0&insecure=0",
		"missing_equals":        "?sni",
		"empty_pair":            "?sni=example&",
		"empty_key":             "?=value",
		"bad_percent":           "?sni=%GG",
		"bad_utf8":              "?sni=%FF",
		"semicolon":             "?sni=example;insecure=1",
		"security":              "?security=reality",
		"empty_security":        "?security=",
		"insecure_bool":         "?insecure=true",
		"insecure_empty":        "?insecure=",
		"empty_sni":             "?sni=",
		"whitespace_sni":        "?sni=example+test",
		"empty_alpn":            "?alpn=",
		"empty_alpn_item":       "?alpn=h3,",
		"whitespace_alpn":       "?alpn=h3,+h2",
		"certificate_pin":       "?pinSHA256=abc",
		"ech":                   "?ech=abc",
		"bandwidth":             "?upmbps=100",
		"hop_ports":             "?mport=443,8443",
		"unknown":               "?future-option=value",
		"path":                  "/unsupported",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseProxyURL("hy2://auth@server.example" + suffix); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
	for _, uri := range []string{
		"hy2://auth@server.example:0", "hy2://auth@server.example:65536",
		"hy2://auth@server.example:", "hy2://auth@server.example:443,8443",
		"hy2://auth@server.example:4000-5000", "hy2://auth@server.example:-1",
		"hy2://user@pass@server.example", "hy2://bad%GG@server.example",
		"hy2://bad%FF@server.example", "hy2://auth@", "hy2://auth@server.example\n",
	} {
		if _, err := parseProxyURL(uri); err == nil {
			t.Errorf("expected rejection of %q", uri)
		}
	}
}

func TestHysteria2ErrorsDoNotEchoCredentials(t *testing.T) {
	const secret = "do-not-print-test-secret"
	for _, uri := range []string{
		"hy2://" + secret + "@server.example:bad", "hy2://" + secret + "%ZZ@server.example",
		"hy2://auth@server.example?obfs=" + secret, "hy2://auth@server.example?unknown=" + secret,
	} {
		_, err := parseProxyURL(uri)
		if err == nil || strings.Contains(err.Error(), secret) {
			t.Fatalf("unsafe or missing error: %v", err)
		}
	}
}

func TestHysteria2ConfigLoadsInXray(t *testing.T) {
	bin := os.Getenv("XRAY_BINARY")
	if bin == "" {
		t.Skip("XRAY_BINARY is not set")
	}
	for _, uri := range []string{
		"hy2://test-user:test-password@127.0.0.1:8443?security=tls&sni=example.com&alpn=h3&obfs=salamander&obfs-password=test-mask",
		"hysteria2://test-auth@[::1]:8443?insecure=0",
	} {
		p, err := parseProxyURL(uri)
		if err != nil {
			t.Fatal(err)
		}
		config, err := json.Marshal(map[string]any{"outbounds": []any{generateOutbound(p, "test", "", "")}})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		cmd := exec.CommandContext(ctx, bin, "run", "-test", "-config", "stdin:")
		cmd.Stdin = bytes.NewReader(config)
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil || !bytes.Contains(output, []byte("Configuration OK")) {
			t.Fatalf("Xray rejected synthetic config: %v\n%s", err, output)
		}
	}
}
