//go:build integration

// Integration test for UserManager. Touches real /etc/passwd, /home,
// /run/netns, /run/stereos. Requires root. Skipped unless built with
// -tags=integration.
//
// Run: sudo -E go test -tags=integration ./pkg/ -run TestSandboxUserLifecycle -v

package stereosd

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

func TestSandboxUserLifecycle(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}

	// Use a name unlikely to collide with anything real.
	name := "iso-probe"
	username := "sb-" + name

	// Pre-clean in case a previous run left state.
	_ = (&UserManager{}).DestroySandboxUser(&SandboxUserPayload{Name: name})

	// Build a tiny fake HM gen with two top-level entries.
	hmDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hmDir, ".zshrc"), []byte("# fake"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(hmDir, ".config"), 0755); err != nil {
		t.Fatal(err)
	}

	mgr := NewUserManager(hmDir)
	payload := &SandboxUserPayload{Name: name}

	// --- Create ---
	if err := mgr.CreateSandboxUser(payload); err != nil {
		t.Fatalf("create: %v", err)
	}
	t.Cleanup(func() { _ = mgr.DestroySandboxUser(payload) })

	u, err := user.Lookup(username)
	if err != nil {
		t.Fatalf("user %s not in /etc/passwd after create: %v", username, err)
	}
	t.Logf("user created: uid=%s home=%s shell=%s", u.Uid, u.HomeDir, u.Username)

	for _, want := range []string{
		"/home/" + username,
		"/home/" + username + "/.zshrc",
		"/home/" + username + "/.config",
		"/run/netns/" + name,
		"/run/stereos/shells/" + username,
	} {
		if _, err := os.Lstat(want); err != nil {
			t.Errorf("expected %s to exist: %v", want, err)
		}
	}

	// .zshrc should be a symlink into the HM gen.
	if dst, err := os.Readlink("/home/" + username + "/.zshrc"); err != nil {
		t.Errorf("readlink .zshrc: %v", err)
	} else if dst != filepath.Join(hmDir, ".zshrc") {
		t.Errorf(".zshrc -> %s, want %s", dst, filepath.Join(hmDir, ".zshrc"))
	}

	// Idempotency: re-create is a no-op.
	if err := mgr.CreateSandboxUser(payload); err != nil {
		t.Errorf("second create should be no-op, got %v", err)
	}

	// --- Destroy ---
	if err := mgr.DestroySandboxUser(payload); err != nil {
		t.Fatalf("destroy: %v", err)
	}

	if _, err := user.Lookup(username); err == nil {
		t.Errorf("user %s still in /etc/passwd after destroy", username)
	}
	for _, gone := range []string{
		"/home/" + username,
		"/run/netns/" + name,
		"/run/stereos/shells/" + username,
	} {
		if _, err := os.Lstat(gone); err == nil {
			t.Errorf("expected %s to be removed", gone)
		}
	}

	// Idempotency: destroy again should not error.
	if err := mgr.DestroySandboxUser(payload); err != nil {
		t.Errorf("second destroy should be no-op, got %v", err)
	}
}
