package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// LoadEnvFile reads KEY=VALUE lines from path into the environment. Values
// already set in the real environment win, so a secrets manager can override
// the file. Returns (false, nil) if the file doesn't exist.
func LoadEnvFile(path string) (bool, error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer f.Close()

	if runtime.GOOS != "windows" {
		if st, err := f.Stat(); err == nil && st.Mode().Perm()&0o077 != 0 {
			return true, fmt.Errorf("%s holds secrets and is readable by other users; run: chmod 600 %s", path, path)
		}
	}

	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return true, fmt.Errorf("%s:%d: expected KEY=VALUE", path, n)
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		if _, set := os.LookupEnv(k); !set {
			_ = os.Setenv(k, v)
		}
	}
	return true, sc.Err()
}

// SetEnvValue writes KEY=value into an existing env file, replacing the line if
// the key is already set, and keeps the file private to its owner.
func SetEnvValue(path, key, value string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	entry, found := key+"="+value, false
	for i, line := range lines {
		k, _, ok := strings.Cut(strings.TrimPrefix(strings.TrimSpace(line), "export "), "=")
		if ok && strings.TrimSpace(k) == key {
			lines[i], found = entry, true
		}
	}
	if !found {
		lines = append(lines, entry)
	}
	target, err := filepath.EvalSymlinks(path) // keep a symlinked sift.env a symlink
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), "sift-*.env") // 0600, and matched by .gitignore
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(strings.Join(lines, "\n") + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), target)
}

// DefaultEnvFile finds sift.env: $SIFT_ENV_FILE, then the working directory,
// then next to the executable.
func DefaultEnvFile() string {
	if p := os.Getenv("SIFT_ENV_FILE"); p != "" {
		return p
	}
	if _, err := os.Stat("sift.env"); err == nil {
		return "sift.env"
	}
	if exe, err := os.Executable(); err == nil {
		return filepath.Join(filepath.Dir(exe), "sift.env")
	}
	return "sift.env"
}
