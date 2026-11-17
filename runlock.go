package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// An exclusive directory-local lock prevents overlapping cron invocations.
// Stale locks deliberately require inspection instead of stealing another run.
func lockOutputDir(dir string) (func(), error) {
	filename := filepath.Join(dir, ".subscription-watcher.lock")
	file, err := os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, fmt.Errorf("не удалось взять блокировку %s: другой запуск или оставшийся lock-файл", filename)
	}
	if _, err := fmt.Fprintf(file, "%d\n", os.Getpid()); err != nil {
		file.Close()
		os.Remove(filename)
		return nil, fmt.Errorf("не удалось записать блокировку")
	}
	if err := file.Close(); err != nil {
		os.Remove(filename)
		return nil, err
	}
	return func() { _ = os.Remove(filename) }, nil
}
