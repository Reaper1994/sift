package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadEnvFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sift.env")
	_ = os.WriteFile(p, []byte("# comment\nSIFT_T_A=\"one\"\nexport SIFT_T_B=two\nSIFT_T_C=file\n"), 0o600)
	t.Setenv("SIFT_T_C", "env-wins")
	os.Unsetenv("SIFT_T_A")
	os.Unsetenv("SIFT_T_B")
	defer os.Unsetenv("SIFT_T_A")
	defer os.Unsetenv("SIFT_T_B")

	if found, err := LoadEnvFile(p); !found || err != nil {
		t.Fatal(found, err)
	}
	if os.Getenv("SIFT_T_A") != "one" || os.Getenv("SIFT_T_B") != "two" || os.Getenv("SIFT_T_C") != "env-wins" {
		t.Fatal("values wrong")
	}
	if found, _ := LoadEnvFile(p + ".missing"); found {
		t.Fatal("missing file reported found")
	}
}

func TestEnvFileRejectsWorldReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	p := filepath.Join(t.TempDir(), "sift.env")
	_ = os.WriteFile(p, []byte("A=b\n"), 0o644)
	if _, err := LoadEnvFile(p); err == nil {
		t.Fatal("accepted world-readable secrets file")
	}
}

func TestSetEnvValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sift.env")
	if err := os.WriteFile(path, []byte("# keep me\nA=1\nB=2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SetEnvValue(path, "A", "new"); err != nil {
		t.Fatal(err)
	}
	if err := SetEnvValue(path, "C", "3"); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if want := "# keep me\nA=new\nB=2\nC=3\n"; string(got) != want {
		t.Fatalf("got %q", got)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(path); st.Mode().Perm() != 0o600 {
			t.Fatalf("mode %v", st.Mode().Perm())
		}
	}
}

func TestSetEnvValueKeepsSymlinkAndLeavesNoTempFile(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real.env")
	link := filepath.Join(dir, "sift.env")
	if err := os.WriteFile(real, []byte("A=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := SetEnvValue(link, "A", "2"); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Lstat(link); st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("symlink was replaced")
	}
	if got, _ := os.ReadFile(real); string(got) != "A=2\n" {
		t.Fatalf("got %q", got)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("left files behind: %v", entries)
	}
}
