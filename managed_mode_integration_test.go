package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mappedModeArgs(t *testing.T, dir, source, backupDir string) []string {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "tags.json")
	writeTestFile(t, filepath.Dir(filename), filepath.Base(filename), `{"rules":[{"name":"*SE #4*","protocol":"hysteria2","tag":"hysteria2-se4"}]}`)
	return []string{"--output-dir", dir, "--no-hwid", "--tag", "test", "--url", source, "--tag-map", filename, "--update-file", "04_outbounds.json", "--backup-dir", backupDir}
}

func TestManagedModeDryRunThenApply(t *testing.T) {
	requireXray(t)
	dir := t.TempDir()
	addr := writeAPIConfig(t, dir)
	const initial = `{"outbounds":[{"tag":"hysteria2-se4","protocol":"freedom"},{"tag":"vless-reality-us9","protocol":"freedom","settings":{"redirect":"unchanged.example.com:443"}}]}`
	const routing = `{"routing":{"rules":[{"type":"field","inboundTag":["force-proxy-redirect","force-proxy-tproxy"],"outboundTag":"hysteria2-se4"}]}}`
	writeTestFile(t, dir, "04_outbounds.json", initial)
	writeTestFile(t, dir, "05_routing.json", routing)
	startXray(t, dir, addr)
	before := listOutbounds(t, addr)
	srv := newSubscriptionServer(t)
	srv.set("sub", "hy2://test-user:test-password@127.0.0.1:8443?security=tls&alpn=h3&sni=example.com&obfs=salamander&obfs-password=test-mask#SE%20%234")
	backupDir := filepath.Join(t.TempDir(), "backups")
	args := mappedModeArgs(t, dir, srv.URL+"/sub", backupDir)
	if err := run(append(append([]string{}, args...), "--dry-run")); err != nil {
		t.Fatal(err)
	}
	assertFileEquals(t, filepath.Join(dir, "04_outbounds.json"), []byte(initial))
	assertDeepEqual(t, listOutbounds(t, addr), before)
	if _, err := os.Stat(backupDir); !os.IsNotExist(err) {
		t.Fatal("dry-run created a backup")
	}
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	after := listOutbounds(t, addr)
	if after["hysteria2-se4"] == before["hysteria2-se4"] || !strings.Contains(after["hysteria2-se4"], "hysteria") {
		t.Fatal("selected outbound was not updated through the API")
	}
	if after["direct"] != before["direct"] || after["vless-reality-us9"] != before["vless-reality-us9"] {
		t.Fatal("unselected runtime outbound changed")
	}
	assertFileEquals(t, filepath.Join(dir, "05_routing.json"), []byte(routing))
	backups, err := os.ReadDir(backupDir)
	if err != nil || len(backups) != 1 {
		t.Fatal("expected one backup")
	}
	assertFileEquals(t, filepath.Join(backupDir, backups[0].Name()), []byte(initial))
	updated := readFile(t, filepath.Join(dir, "04_outbounds.json"))
	if err := run(args); err != nil {
		t.Fatal(err)
	}
	assertFileEquals(t, filepath.Join(dir, "04_outbounds.json"), updated)
	backups, _ = os.ReadDir(backupDir)
	if len(backups) != 1 {
		t.Fatal("unchanged subscription created another backup")
	}
}

func TestManagedModeCrossFileCollisionStopsBeforeFetching(t *testing.T) {
	requireXray(t)
	for _, sibling := range []string{"99_duplicate.json", "99_duplicate.jsonc"} {
		t.Run(sibling, func(t *testing.T) {
			dir := t.TempDir()
			const initial = `{"outbounds":[{"tag":"hysteria2-se4","protocol":"freedom"}]}`
			writeTestFile(t, dir, "04_outbounds.json", initial)
			writeTestFile(t, dir, sibling, initial)
			srv := newHeaderRecorder(t, "hy2://fake@example.com#SE%20%234")
			args := mappedModeArgs(t, dir, srv.URL, filepath.Join(t.TempDir(), "backups"))
			if err := run(append(args, "--no-restart")); err == nil {
				t.Fatal("duplicate tag was accepted")
			}
			if srv.count() != 0 {
				t.Fatal("subscription fetched before detecting duplicate ownership")
			}
			assertFileEquals(t, filepath.Join(dir, "04_outbounds.json"), []byte(initial))
		})
	}
}

func TestManagedModeMissingNodePreservesFile(t *testing.T) {
	requireXray(t)
	dir := t.TempDir()
	const initial = `{"outbounds":[{"tag":"hysteria2-se4","protocol":"freedom"}]}`
	writeTestFile(t, dir, "04_outbounds.json", initial)
	srv := newHeaderRecorder(t, "hy2://fake@example.com#DE%20%231")
	backupDir := filepath.Join(t.TempDir(), "backups")
	args := mappedModeArgs(t, dir, srv.URL, backupDir)
	if err := run(append(args, "--no-restart")); err == nil {
		t.Fatal("missing selected node must fail")
	}
	assertFileEquals(t, filepath.Join(dir, "04_outbounds.json"), []byte(initial))
	if _, err := os.Stat(backupDir); !os.IsNotExist(err) {
		t.Fatal("failure created a backup")
	}
}

func TestURLFileLoadsWithoutPrintingSecret(t *testing.T) {
	dir := t.TempDir()
	srv := newHeaderRecorder(t, "hy2://fake@example.com#node")
	filename := filepath.Join(t.TempDir(), "subscription.url")
	writeTestFile(t, filepath.Dir(filename), filepath.Base(filename), srv.URL+"?token=private\n")
	if err := run([]string{"--tag", "test", "--url-file", filename, "--output-dir", dir, "--no-hwid", "--no-restart"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "04_outbounds.test.json")); err != nil {
		t.Fatal(err)
	}
}
