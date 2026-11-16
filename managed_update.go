package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Xray 26.6.1's confdir loader recognizes these suffixes case-sensitively.
func isXrayConfigFile(name string) bool {
	switch filepath.Ext(name) {
	case ".json", ".jsonc", ".toml", ".yaml", ".yml":
		return true
	default:
		return false
	}
}

// validatePendingUpdates tests the entire candidate configuration in an owned,
// private staging directory. Xray never reads a partially changed live directory.
func validatePendingUpdates(confdir string, updates []*pendingUpdate) error {
	base, err := filepath.Abs(confdir)
	if err != nil {
		return err
	}
	stage, err := os.MkdirTemp("", "xkeen-candidate-*")
	if err != nil {
		return fmt.Errorf("create validation directory: %w", err)
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0700); err != nil {
		return err
	}
	entries, err := os.ReadDir(base)
	if err != nil {
		return fmt.Errorf("read configuration directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !isXrayConfigFile(entry.Name()) {
			continue
		}
		content, err := os.ReadFile(filepath.Join(base, entry.Name()))
		if err != nil {
			return fmt.Errorf("read configuration %q: %w", entry.Name(), err)
		}
		if err := os.WriteFile(filepath.Join(stage, entry.Name()), content, 0600); err != nil {
			return err
		}
	}
	seen := make(map[string]bool)
	for _, update := range updates {
		if update == nil {
			return fmt.Errorf("nil pending update")
		}
		path, err := filepath.Abs(update.path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, path)
		if err != nil || filepath.Dir(rel) != "." || filepath.Ext(rel) != ".json" {
			return fmt.Errorf("update target must be a JSON file directly inside configuration directory")
		}
		key := rel
		if os.PathSeparator == '\\' {
			key = strings.ToLower(key)
		}
		if seen[key] {
			return fmt.Errorf("duplicate update target %q", rel)
		}
		seen[key] = true
		if err := ensureUpdateUnchanged(update); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(stage, rel), update.newContent, 0600); err != nil {
			return err
		}
	}
	if _, err := runXray(xrayDumpTimeout, nil, "run", "-test", "-confdir", stage); err != nil {
		return fmt.Errorf("candidate configuration rejected by native Xray: %w", err)
	}
	return nil
}

// backupPendingUpdate must succeed before applying any managed update. Only the
// original bytes are retained; the unique .bak file is never an Xray input.
func backupPendingUpdate(update *pendingUpdate, backupDir string) error {
	if err := ensureUpdateUnchanged(update); err != nil {
		return err
	}
	if update.oldContent == nil {
		return nil
	}
	base, err := filepath.Abs(filepath.Dir(update.path))
	if err != nil {
		return err
	}
	backupPath, err := filepath.Abs(backupDir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(base, backupPath)
	if err != nil || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
		return fmt.Errorf("backup directory must be outside the configuration directory")
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	// Never change permissions on a user-selected existing directory (for
	// example /tmp). MkdirAll creates missing directories privately; inspect the
	// final directory too, including when another process created it concurrently.
	info, err := os.Stat(backupDir)
	if err != nil {
		return fmt.Errorf("inspect backup directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("backup path is not a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("existing backup directory must be private (no group or other permissions)")
	}
	file, err := os.CreateTemp(backupDir, filepath.Base(update.path)+".*.bak")
	if err != nil {
		return fmt.Errorf("create backup: %w", err)
	}
	complete := false
	defer func() {
		file.Close()
		if !complete {
			os.Remove(file.Name())
		}
	}()
	if err := file.Chmod(0600); err != nil {
		return fmt.Errorf("secure backup: %w", err)
	}
	if _, err := file.Write(update.oldContent); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync backup: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close backup: %w", err)
	}
	complete = true
	return nil
}

func ensureUpdateUnchanged(update *pendingUpdate) error {
	if update == nil {
		return fmt.Errorf("nil pending update")
	}
	current, err := os.ReadFile(update.path)
	if update.oldContent == nil && errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read update target %s: %w", update.path, err)
	}
	if update.oldContent == nil || !bytes.Equal(current, update.oldContent) {
		return fmt.Errorf("update target %s changed since preparation; refusing to overwrite", update.path)
	}
	return nil
}

type managedAppliedChange struct {
	tag string
	old map[string]any
}

func managedOutboundIndex(outbounds []map[string]any) (map[string]map[string]any, error) {
	index := make(map[string]map[string]any, len(outbounds))
	for _, outbound := range outbounds {
		tag := outboundTag(outbound)
		if tag == "" {
			return nil, fmt.Errorf("managed configuration contains an outbound without a tag")
		}
		if _, found := index[tag]; found {
			return nil, fmt.Errorf("managed configuration contains duplicate tag %q", tag)
		}
		index[tag] = outbound
	}
	return index, nil
}

func applyManagedUpdate(api outboundAPI, update *pendingUpdate) error {
	return applyManagedUpdateWithWriter(api, update, update.write)
}

func applyManagedUpdateWithWriter(api outboundAPI, update *pendingUpdate, write func([]byte) error) error {
	if err := ensureUpdateUnchanged(update); err != nil {
		return err
	}
	if bytes.Equal(update.oldContent, update.newContent) {
		return nil
	}
	oldOutbounds, err := parseOutboundsFile(update.oldContent)
	if err != nil {
		return fmt.Errorf("parse original outbounds: %w", err)
	}
	newOutbounds, err := parseOutboundsFile(update.newContent)
	if err != nil {
		return fmt.Errorf("parse candidate outbounds: %w", err)
	}
	oldByTag, err := managedOutboundIndex(oldOutbounds)
	if err != nil {
		return err
	}
	if _, err := managedOutboundIndex(newOutbounds); err != nil {
		return err
	}
	changes := diffOutbounds(oldOutbounds, newOutbounds)
	if len(changes.removals) > 0 {
		return fmt.Errorf("managed updates cannot remove outbound tags")
	}
	var applied []managedAppliedChange
	rollback := func(cause error) error {
		errs := []error{cause}
		for i := len(applied) - 1; i >= 0; i-- {
			change := applied[i]
			// A failed API response may follow a successful remote mutation. Remove
			// the possibly present new version even when the original call failed.
			if err := api.removeOutbound(change.tag); err != nil {
				errs = append(errs, fmt.Errorf("rollback remove %q failed: %w", change.tag, err))
			}
			if change.old != nil {
				if err := api.addOutbound(change.old); err != nil {
					errs = append(errs, fmt.Errorf("rollback restore %q failed: %w", change.tag, err))
				}
			}
		}
		return errors.Join(errs...)
	}
	for _, outbound := range changes.upserts {
		tag := outboundTag(outbound)
		old := oldByTag[tag]
		// Journal BEFORE the first attempted mutation, including brand-new tags.
		// Xray may register/remove a handler before returning an error.
		applied = append(applied, managedAppliedChange{tag: tag, old: old})
		if old != nil {
			if err := api.removeOutbound(tag); err != nil {
				return rollback(fmt.Errorf("remove outbound %q failed: %w", tag, err))
			}
		}
		if err := api.addOutbound(outbound); err != nil {
			return rollback(fmt.Errorf("add outbound %q failed: %w", tag, err))
		}
	}
	if err := ensureUpdateUnchanged(update); err != nil {
		return rollback(err)
	}
	if err := write(update.newContent); err != nil {
		return rollback(fmt.Errorf("persist managed update failed: %w", err))
	}
	return nil
}
