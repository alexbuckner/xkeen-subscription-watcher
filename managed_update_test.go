package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type managedMockAPI struct {
	state         map[string]map[string]any
	calls         []string
	fail          func(string, map[string]any) error
	afterAdd      func()
	afterMutation func(string, map[string]any) error
}

func (api *managedMockAPI) addOutbound(outbound map[string]any) error {
	tag := outboundTag(outbound)
	api.calls = append(api.calls, "add:"+tag)
	if api.fail != nil {
		if err := api.fail("add:"+tag, outbound); err != nil {
			return err
		}
	}
	if _, exists := api.state[tag]; exists {
		return errors.New("already exists")
	}
	api.state[tag] = outbound
	if api.afterMutation != nil {
		if err := api.afterMutation("add:"+tag, outbound); err != nil {
			return err
		}
	}
	if api.afterAdd != nil {
		api.afterAdd()
	}
	return nil
}

func (api *managedMockAPI) removeOutbound(tag string) error {
	api.calls = append(api.calls, "remove:"+tag)
	if api.fail != nil {
		if err := api.fail("remove:"+tag, nil); err != nil {
			return err
		}
	}
	delete(api.state, tag)
	if api.afterMutation != nil {
		if err := api.afterMutation("remove:"+tag, nil); err != nil {
			return err
		}
	}
	return nil
}

func managedFixture(t *testing.T, oldJSON, newJSON string) (*pendingUpdate, *managedMockAPI) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "04_outbounds.json")
	if err := os.WriteFile(path, []byte(oldJSON), 0600); err != nil {
		t.Fatal(err)
	}
	old, err := parseOutboundsFile([]byte(oldJSON))
	if err != nil {
		t.Fatal(err)
	}
	return &pendingUpdate{path: path, oldContent: []byte(oldJSON), newContent: []byte(newJSON)}, &managedMockAPI{state: outboundsByTag(old)}
}

const managedOld = `{"outbounds":[{"tag":"a","protocol":"freedom"},{"tag":"foreign","protocol":"blackhole"}]}`
const managedNew = `{"outbounds":[{"tag":"a","protocol":"blackhole"},{"tag":"foreign","protocol":"blackhole"},{"tag":"b","protocol":"freedom"}]}`

func assertManagedOriginal(t *testing.T, update *pendingUpdate, api *managedMockAPI) {
	t.Helper()
	content, err := os.ReadFile(update.path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(content, update.oldContent) {
		t.Fatal("original file was changed")
	}
	old, _ := parseOutboundsFile(update.oldContent)
	if !reflect.DeepEqual(api.state, outboundsByTag(old)) {
		t.Fatalf("runtime not restored: %#v", api.state)
	}
}

func TestManagedBackupExactUniqueAndPrivate(t *testing.T) {
	update, _ := managedFixture(t, managedOld, managedNew)
	dir := filepath.Join(t.TempDir(), "backups")
	for i := 0; i < 2; i++ {
		if err := backupPendingUpdate(update, dir); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 2 {
		t.Fatalf("backups: %v %v", entries, err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".bak") {
			t.Fatalf("unexpected backup name %s", entry.Name())
		}
		path := filepath.Join(dir, entry.Name())
		content, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(content, update.oldContent) {
			t.Fatalf("backup bytes mismatch: %v", err)
		}
		if runtime.GOOS != "windows" {
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0600 {
				t.Fatalf("backup mode %o", info.Mode().Perm())
			}
		}
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(dir)
		if info.Mode().Perm() != 0700 {
			t.Fatalf("directory mode %o", info.Mode().Perm())
		}
	}
}

func TestManagedBackupRejectsExistingSharedDirectoryWithoutChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are not represented by Windows chmod/stat")
	}
	update, _ := managedFixture(t, managedOld, managedNew)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0777); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := backupPendingUpdate(update, dir); err == nil {
		t.Fatal("shared backup directory accepted")
	}
	after, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("existing permissions changed: %o -> %o", before.Mode().Perm(), after.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("backup was written despite rejected directory: %v %v", entries, err)
	}
}

func TestManagedExternalDriftAbortsBeforeAPI(t *testing.T) {
	update, api := managedFixture(t, managedOld, managedNew)
	if err := os.WriteFile(update.path, []byte("external"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := applyManagedUpdate(api, update); err == nil {
		t.Fatal("expected drift rejection")
	}
	if len(api.calls) != 0 {
		t.Fatalf("API called: %v", api.calls)
	}
	if err := backupPendingUpdate(update, filepath.Join(t.TempDir(), "backup")); err == nil {
		t.Fatal("backup should reject stale original")
	}
}

func TestManagedFailedAddRestoresOld(t *testing.T) {
	update, api := managedFixture(t, managedOld, managedNew)
	api.fail = func(call string, outbound map[string]any) error {
		if call == "add:a" && outbound["protocol"] == "blackhole" {
			return errors.New("injected add failure")
		}
		return nil
	}
	if err := applyManagedUpdate(api, update); err == nil {
		t.Fatal("expected failure")
	}
	assertManagedOriginal(t, update, api)
	want := []string{"remove:a", "add:a", "remove:a", "add:a"}
	if !reflect.DeepEqual(api.calls, want) {
		t.Fatalf("calls %v, want %v", api.calls, want)
	}
}

func TestManagedLaterFailureRollsBackEarlierTag(t *testing.T) {
	update, api := managedFixture(t, managedOld, managedNew)
	api.fail = func(call string, _ map[string]any) error {
		if call == "add:b" {
			return errors.New("injected later failure")
		}
		return nil
	}
	if err := applyManagedUpdate(api, update); err == nil {
		t.Fatal("expected failure")
	}
	assertManagedOriginal(t, update, api)
	want := []string{"remove:a", "add:a", "add:b", "remove:b", "remove:a", "add:a"}
	if !reflect.DeepEqual(api.calls, want) {
		t.Fatalf("calls %v, want %v", api.calls, want)
	}
}

func TestManagedMutationBeforeErrorIsRolledBack(t *testing.T) {
	for _, failingCall := range []string{"remove:a", "add:a", "add:b"} {
		t.Run(failingCall, func(t *testing.T) {
			update, api := managedFixture(t, managedOld, managedNew)
			failed := false
			api.afterMutation = func(call string, _ map[string]any) error {
				if call == failingCall && !failed {
					failed = true
					return errors.New("remote mutation succeeded but response failed")
				}
				return nil
			}
			err := applyManagedUpdate(api, update)
			if err == nil || !strings.Contains(err.Error(), "response failed") {
				t.Fatalf("original failure not reported: %v", err)
			}
			if !failed {
				t.Fatal("failure injection was not reached")
			}
			assertManagedOriginal(t, update, api)
		})
	}
}

func TestManagedUnavailableAPIRollbackFailureReported(t *testing.T) {
	update, api := managedFixture(t, managedOld, managedNew)
	api.fail = func(string, map[string]any) error { return errors.New("API unavailable") }
	err := applyManagedUpdate(api, update)
	if err == nil || !strings.Contains(err.Error(), "rollback remove") || !strings.Contains(err.Error(), "rollback restore") {
		t.Fatalf("rollback failure not explicit: %v", err)
	}
	assertManagedOriginal(t, update, api)
}

func TestManagedWriteFailureRollsBack(t *testing.T) {
	update, api := managedFixture(t, managedOld, managedNew)
	err := applyManagedUpdateWithWriter(api, update, func([]byte) error { return errors.New("injected write failure") })
	if err == nil || !strings.Contains(err.Error(), "write failure") {
		t.Fatalf("unexpected error: %v", err)
	}
	assertManagedOriginal(t, update, api)
	want := []string{"remove:a", "add:a", "add:b", "remove:b", "remove:a", "add:a"}
	if !reflect.DeepEqual(api.calls, want) {
		t.Fatalf("calls %v, want %v", api.calls, want)
	}
}

func TestManagedRollbackFailureIsReported(t *testing.T) {
	update, api := managedFixture(t, managedOld, managedNew)
	api.fail = func(call string, outbound map[string]any) error {
		if call == "add:b" {
			return errors.New("original failure")
		}
		if call == "add:a" && outbound["protocol"] == "freedom" {
			return errors.New("restore failed")
		}
		return nil
	}
	err := applyManagedUpdate(api, update)
	if err == nil || !strings.Contains(err.Error(), "original failure") || !strings.Contains(err.Error(), "rollback restore") {
		t.Fatalf("aggregate error: %v", err)
	}
	content, _ := os.ReadFile(update.path)
	if !bytes.Equal(content, update.oldContent) {
		t.Fatal("file changed despite rollback failure")
	}
}

func TestManagedNoChangeAndForeignTags(t *testing.T) {
	update, api := managedFixture(t, managedOld, managedOld)
	if err := applyManagedUpdateWithWriter(api, update, func([]byte) error { t.Fatal("unexpected write"); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(api.calls) != 0 {
		t.Fatal(api.calls)
	}
	update.newContent = []byte(managedNew)
	if err := applyManagedUpdate(api, update); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(api.calls, []string{"remove:a", "add:a", "add:b"}) {
		t.Fatalf("foreign tag touched or new tag removed: %v", api.calls)
	}
	content, _ := os.ReadFile(update.path)
	if !bytes.Equal(content, update.newContent) {
		t.Fatal("candidate not persisted")
	}
}

func TestManagedDriftDuringApplyRollsBack(t *testing.T) {
	update, api := managedFixture(t, managedOld, managedNew)
	api.afterAdd = func() {
		if err := os.WriteFile(update.path, []byte("external"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := applyManagedUpdate(api, update); err == nil {
		t.Fatal("expected late drift rejection")
	}
	old, _ := parseOutboundsFile(update.oldContent)
	if !reflect.DeepEqual(api.state, outboundsByTag(old)) {
		t.Fatal("runtime not restored")
	}
	content, _ := os.ReadFile(update.path)
	if string(content) != "external" {
		t.Fatal("external edit overwritten")
	}
}

func TestManagedRejectsRemovalsAndDuplicateTags(t *testing.T) {
	for _, candidate := range []string{`{"outbounds":[]}`, `{"outbounds":[{"tag":"a"},{"tag":"a"}]}`} {
		update, api := managedFixture(t, managedOld, candidate)
		if err := applyManagedUpdate(api, update); err == nil {
			t.Fatalf("accepted %s", candidate)
		}
		if len(api.calls) != 0 {
			t.Fatal(api.calls)
		}
	}
}

func TestManagedEnsureAbsentAndReadErrors(t *testing.T) {
	update := &pendingUpdate{path: filepath.Join(t.TempDir(), "missing.json")}
	if err := ensureUpdateUnchanged(update); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(update.path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := ensureUpdateUnchanged(update); err == nil {
		t.Fatal("directory read error accepted")
	}
}

func TestManagedNativeValidationKeepsOriginal(t *testing.T) {
	requireXray(t)
	dir := t.TempDir()
	writeTestFile(t, dir, "00_base.json", `{"log":{"loglevel":"none"}}`)
	path := filepath.Join(dir, "04_outbounds.json")
	old := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
	if err := os.WriteFile(path, old, 0600); err != nil {
		t.Fatal(err)
	}
	update := &pendingUpdate{path: path, oldContent: old, newContent: old}
	if err := validatePendingUpdates(dir, []*pendingUpdate{update}); err != nil {
		t.Fatalf("valid candidate rejected: %v", err)
	}
	for _, invalid := range []string{`{"outbounds":`, `{"outbounds":[{"tag":"direct","protocol":"invalid-native-protocol"}]}`} {
		update.newContent = []byte(invalid)
		if err := validatePendingUpdates(dir, []*pendingUpdate{update}); err == nil {
			t.Fatal("invalid native candidate accepted")
		}
		got, _ := os.ReadFile(path)
		if !bytes.Equal(got, old) {
			t.Fatal("validation modified production file")
		}
	}
	// A separate JSON file must also be staged and validated.
	writeTestFile(t, dir, "99_invalid.json", `{"inbounds":`)
	update.newContent = old
	if err := validatePendingUpdates(dir, []*pendingUpdate{update}); err == nil {
		t.Fatal("unmodified invalid JSON file was omitted")
	}
}

func TestManagedNativeValidationStagesEveryConsumedExtension(t *testing.T) {
	requireXray(t)
	for _, extension := range []string{".json", ".jsonc", ".toml", ".yaml", ".yml", ".JSON", ".JSONC", ".TOML", ".YAML", ".YML", ".txt"} {
		t.Run(extension, func(t *testing.T) {
			dir := t.TempDir()
			old := []byte(`{"outbounds":[{"tag":"direct","protocol":"freedom"}]}`)
			path := filepath.Join(dir, "04_outbounds.json")
			if err := os.WriteFile(path, old, 0600); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, dir, "99_invalid"+extension, "not valid: [[[")
			update := &pendingUpdate{path: path, oldContent: old, newContent: old}
			_, nativeErr := runXray(xrayDumpTimeout, nil, "run", "-test", "-confdir", dir)
			stagedErr := validatePendingUpdates(dir, []*pendingUpdate{update})
			wantConsumed := extension == strings.ToLower(extension) && extension != ".txt"
			if isXrayConfigFile("99_invalid"+extension) != wantConsumed {
				t.Fatal("extension predicate differs from pinned case-sensitive behavior")
			}
			if (nativeErr != nil) != wantConsumed {
				t.Fatalf("pinned native loader behavior changed for %s: %v", extension, nativeErr)
			}
			if (stagedErr != nil) != (nativeErr != nil) {
				t.Fatalf("staging differs from native for %s: native=%v staged=%v", extension, nativeErr, stagedErr)
			}
			content, _ := os.ReadFile(path)
			if !bytes.Equal(content, old) {
				t.Fatal("validation changed original file")
			}
		})
	}
}

func TestManagedValidationRejectsTargetsOutsideDirectory(t *testing.T) {
	dir := t.TempDir()
	update := &pendingUpdate{path: filepath.Join(t.TempDir(), "outside.json"), newContent: []byte(`{}`)}
	if err := validatePendingUpdates(dir, []*pendingUpdate{update}); err == nil {
		t.Fatal("outside target accepted")
	}
}

func TestManagedRunXrayErrorDoesNotExposeOutput(t *testing.T) {
	requireXray(t)
	secret := "managed-test-secret-credential"
	_, err := runXray(xrayDumpTimeout, []byte(fmt.Sprintf(`{"outbounds":[{"protocol":%q}]}`, secret)), "run", "-test", "-config", "stdin:")
	if err == nil {
		t.Fatal("expected native rejection")
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("error exposed native process output")
	}
}
