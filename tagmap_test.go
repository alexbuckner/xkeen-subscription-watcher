package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testTagRules(t *testing.T, document string) []tagRule {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "tags.json")
	if err := os.WriteFile(filename, []byte(document), 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := loadTagRules(filename)
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func TestMappedHysteriaKeepsRoutingTagAcrossEndpointChanges(t *testing.T) {
	rules := testTagRules(t, `{"rules":[{"name":"*SE #4*","protocol":"hy2","tag":"hysteria2-se4"}]}`)
	for _, host := range []string{"old.example.com", "rotated.example.com"} {
		uri := "hy2://user:pass@" + host + ":443?obfs=salamander&obfs-password=fake&alpn=h3#SE%20%234"
		outbounds, err := getMappedOutbounds([]string{uri, uri}, config{tagRules: rules})
		if err != nil {
			t.Fatal(err)
		}
		outbound := outbounds[0].(map[string]any)
		if outbound["tag"] != "hysteria2-se4" || outbound["settings"].(map[string]any)["address"] != host {
			t.Fatal("mapping changed the routing tag or failed to refresh the endpoint")
		}
	}
}

func TestMappedNodesRequireUniqueMatch(t *testing.T) {
	rules := testTagRules(t, `{"rules":[{"name":"*SE #4*","protocol":"hysteria2","tag":"hysteria2-se4"}]}`)
	for _, nodes := range [][]string{
		{},
		{"hy2://auth@a.example.com#SE%20%234", "hy2://auth@b.example.com#SE%20%234"},
		{"hy2://auth@a.example.com?obfs=unknown#SE%20%234"},
	} {
		if _, err := getMappedOutbounds(nodes, config{tagRules: rules}); err == nil {
			t.Fatal("missing, ambiguous or invalid source must stop a mapped update")
		}
	}
}

func TestMappedVlessKeepsExplicitUDP443FlowAndTransport(t *testing.T) {
	rules := testTagRules(t, `{"rules":[{"name":"*US #9*","protocol":"vless","network":"tcp","security":"reality","tag":"vless-reality-us9","flow":"xtls-rprx-vision-udp443"}]}`)
	nodes := []string{
		"vless://11111111-2222-3333-4444-555555555555@tcp.example.com?type=raw&security=reality#US%20%239",
		"vless://11111111-2222-3333-4444-555555555555@xhttp.example.com?type=xhttp&security=reality#US%20%239",
	}
	generated, err := getMappedOutbounds(nodes, config{tagRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := marshalOutbounds(generated)
	var document struct {
		Outbounds []struct {
			Tag      string `json:"tag"`
			Settings struct {
				Vnext []struct {
					Address string `json:"address"`
					Users   []struct {
						Flow string `json:"flow"`
					} `json:"users"`
				} `json:"vnext"`
			} `json:"settings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(payload, &document); err != nil {
		t.Fatal(err)
	}
	got := document.Outbounds[0]
	if got.Tag != "vless-reality-us9" || got.Settings.Vnext[0].Address != "tcp.example.com" || got.Settings.Vnext[0].Users[0].Flow != "xtls-rprx-vision-udp443" {
		t.Fatal("wrong profile selected or flow override lost")
	}
}

func TestManagedMergePreservesOtherProfilesAndTopLevelFields(t *testing.T) {
	original := []byte(`{"other":{"large":9007199254740993,"unicode":"тест"},"outbounds":[{"tag":"direct","protocol":"freedom","settings":{"domainStrategy":"UseIPv4"}},{"tag":"hysteria2-se4","protocol":"freedom"},{"tag":"vless-reality-in1","protocol":"freedom","settings":{"redirect":"unchanged.example.com"}}]}`)
	updated, err := mergeManagedOutbounds(original, []any{map[string]any{"tag": "hysteria2-se4", "protocol": "hysteria", "settings": map[string]any{"version": 2}}})
	if err != nil {
		t.Fatal(err)
	}
	var before, after map[string]json.RawMessage
	json.Unmarshal(original, &before)
	json.Unmarshal(updated, &after)
	if !bytes.Contains(after["other"], []byte("9007199254740993")) || !equalJSON(before["other"], after["other"]) {
		t.Fatal("unrelated metadata changed")
	}
	oldOutbounds, _ := parseOutboundsFile(original)
	newOutbounds, _ := parseOutboundsFile(updated)
	if len(newOutbounds) != len(oldOutbounds) {
		t.Fatal("outbound count changed")
	}
	for _, i := range []int{0, 2} {
		assertDeepEqual(t, newOutbounds[i], oldOutbounds[i])
	}
	if outboundTag(newOutbounds[1]) != "hysteria2-se4" || newOutbounds[1]["protocol"] != "hysteria" {
		t.Fatal("selected tag did not stay in its original position")
	}
}

func TestManagedMergeRefusesUnknownAndDuplicateTags(t *testing.T) {
	for _, original := range []string{
		`{"outbounds":[{"tag":"other"}]}`,
		`{"outbounds":[{"tag":"wanted"},{"tag":"wanted"}]}`,
		`{"outbounds":[{"protocol":"freedom"}]}`,
	} {
		if _, err := mergeManagedOutbounds([]byte(original), []any{map[string]any{"tag": "wanted"}}); err == nil {
			t.Fatal("expected unsafe merge rejection")
		}
	}
}

func TestManagedRefreshPreservesLocalPolicyAndHysteriaDefaults(t *testing.T) {
	vlessURI := "vless://11111111-2222-3333-4444-555555555555@new.example.com?type=tcp&security=none"
	p, _ := parseProxyURL(vlessURI)
	generated := generateOutbound(p, "vless", "", "")
	original := []byte(`{"outbounds":[{"tag":"vless","protocol":"vless","sendThrough":"192.0.2.1","mux":{"enabled":false},"settings":{"packetEncoding":"xudp","vnext":[{"address":"old.example.com","port":443,"users":[{"id":"11111111-2222-3333-4444-555555555555","level":8,"email":"local-account"}]}]},"streamSettings":{"sockopt":{"mark":61}}}]}`)
	updated, err := mergeManagedOutbounds(original, []any{generated})
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := parseOutboundsFile(updated)
	got := parsed[0]
	settings := got["settings"].(map[string]any)
	user := settings["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if user["level"] != float64(8) || user["email"] != "local-account" || settings["packetEncoding"] != "xudp" || got["sendThrough"] != "192.0.2.1" {
		t.Fatal("local outbound policy was lost")
	}
	if got["streamSettings"].(map[string]any)["sockopt"].(map[string]any)["mark"] != float64(61) {
		t.Fatal("local socket policy was lost")
	}
	if settings["vnext"].([]any)[0].(map[string]any)["address"] != "new.example.com" {
		t.Fatal("server address failed to refresh")
	}
	hys, _ := parseProxyURL("hy2://fake@example.com?alpn=h3")
	old := generateOutbound(hys, "hy2", "", "")
	delete(old["streamSettings"].(map[string]any)["hysteriaSettings"].(map[string]any), "keepAlivePeriod")
	delete(old["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any), "allowInsecure")
	oldBytes, _ := marshalOutbounds([]any{old})
	refreshed, err := mergeManagedOutbounds(oldBytes, []any{generateOutbound(hys, "hy2", "", "")})
	if err != nil || !equalJSON(oldBytes, refreshed) {
		t.Fatal("unchanged subscription changed local keepalive or TLS defaults")
	}
}

func TestTagMapValidation(t *testing.T) {
	for _, document := range []string{
		`{"rules":[]}`,
		`{"rules":[{"name":"*","protocol":"vless","tag":"a","typo":true}]}`,
		`{"rules":[{"name":"[","protocol":"vless","tag":"a"}]}`,
		`{"rules":[{"name":"*","protocol":"hysteria2","tag":"a","flow":"xtls-rprx-vision"}]}`,
		`{"rules":[{"name":"*","protocol":"vless","tag":"a"},{"name":"*","protocol":"vless","tag":"a"}]}`,
	} {
		filename := filepath.Join(t.TempDir(), "tags.json")
		os.WriteFile(filename, []byte(document), 0600)
		if _, err := loadTagRules(filename); err == nil {
			t.Fatalf("accepted invalid tag map %s", document)
		}
	}
}

func TestHy2AndUnpaddedSubscriptionInput(t *testing.T) {
	uri := "hy2://fake@example.com#SE%20%234"
	for _, body := range []string{uri, base64.RawStdEncoding.EncodeToString([]byte(uri)), base64.RawURLEncoding.EncodeToString([]byte(uri))} {
		assertDeepEqual(t, parseSubscriptionResponse(body), []string{uri})
	}
	assertDeepEqual(t, parseSubscriptionResponse("HY2://fake@example.com#SE%20%234"), []string{uri})
	if rawProxyName("hy2://fake@example.com#SE #4 + test") != "SE #4 + test" {
		t.Fatal("fragment characters were treated as query syntax")
	}
}

func TestUnselectedUnsupportedNodeDoesNotBlockMappedUpdate(t *testing.T) {
	rules := testTagRules(t, `{"rules":[{"name":"*SE #4*","protocol":"hysteria2","tag":"hysteria2-se4"}]}`)
	_, err := getMappedOutbounds([]string{
		"hy2://auth@other.example.com?pinSHA256=unsupported#DE%20%231",
		"hy2://auth@selected.example.com#SE%20%234",
	}, config{tagRules: rules})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMappedVlessOmittedTypeDefaultsToTCP(t *testing.T) {
	rules := testTagRules(t, `{"rules":[{"name":"*US #9*","protocol":"vless","network":"tcp","security":"reality","tag":"vless-reality-us9"}]}`)
	outbounds, err := getMappedOutbounds([]string{"vless://11111111-2222-3333-4444-555555555555@example.com?security=reality#US%20%239"}, config{tagRules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if outbounds[0].(map[string]any)["streamSettings"].(map[string]any)["network"] != "tcp" {
		t.Fatal("missing transport did not default to TCP")
	}
}

func TestSubscriptionSecretsStayOutOfLogsAndErrors(t *testing.T) {
	const secret = "PRIVATE_TOKEN_DO_NOT_LOG"
	srv := newTestServer(map[string]testResponse{
		"/sub":  {body: "hy2://" + secret + "@example.com?obfs=bad#SE%20%234"},
		"/fail": {statusCode: 403, body: secret},
	})
	defer srv.Close()
	var logs bytes.Buffer
	oldLog := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(oldLog) })
	rules := testTagRules(t, `{"rules":[{"name":"*SE #4*","protocol":"hysteria2","tag":"hysteria2-se4"}]}`)
	_, err := getOutbounds(subscription{tag: "test", url: srv.URL + "/sub?token=" + secret}, config{tagRules: rules})
	if err == nil || strings.Contains(err.Error()+logs.String(), secret) {
		t.Fatal("parse failure leaked credentials or was not rejected")
	}
	_, err = doHTTPRequest(srv.URL+"/fail?token="+secret, false, nil)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("HTTP error leaked a response body or URL")
	}
}

func TestOutputLockExcludesConcurrentRun(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockOutputDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockOutputDir(dir); err == nil {
		t.Fatal("second process acquired the same lock")
	}
	unlock()
	unlock, err = lockOutputDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	unlock()
}
