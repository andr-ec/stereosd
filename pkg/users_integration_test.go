//go:build integration

// Integration test for UserManager. Touches real /etc/passwd, /home,
// /run/netns, /run/stereos. Requires root. Skipped unless built with
// -tags=integration.
//
// Run: sudo /tmp/users-integration-test -test.v
//   (build with `go test -tags=integration -c -o /tmp/users-integration-test ./pkg/`)

package stereosd

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// cleanupSandbox is the test belt-and-suspenders teardown: always run
// it on t.Cleanup, even when the test under test is supposed to do it,
// so a flaky case can't leak system state into the next run.
func cleanupSandbox(t *testing.T, name string) {
	t.Helper()
	mgr := &UserManager{}
	if err := mgr.DestroySandboxUser(&SandboxUserPayload{Name: name}); err != nil {
		t.Logf("cleanup destroy %s: %v (probably already clean)", name, err)
	}
}

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

// Two sandboxes side-by-side: independent homes, independent UIDs,
// independent netns. Killing one doesn't disturb the other.
func TestTwoSandboxesAreIndependent(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}

	mgr := NewUserManager("")
	a, b := "iso-twin-a", "iso-twin-b"
	_ = mgr.DestroySandboxUser(&SandboxUserPayload{Name: a})
	_ = mgr.DestroySandboxUser(&SandboxUserPayload{Name: b})
	t.Cleanup(func() { cleanupSandbox(t, a); cleanupSandbox(t, b) })

	if err := mgr.CreateSandboxUser(&SandboxUserPayload{Name: a}); err != nil {
		t.Fatalf("create a: %v", err)
	}
	if err := mgr.CreateSandboxUser(&SandboxUserPayload{Name: b}); err != nil {
		t.Fatalf("create b: %v", err)
	}

	ua, _ := user.Lookup("sb-" + a)
	ub, _ := user.Lookup("sb-" + b)
	if ua.Uid == ub.Uid {
		t.Errorf("expected distinct UIDs, both got %s", ua.Uid)
	}
	if ua.HomeDir == ub.HomeDir {
		t.Errorf("expected distinct homes, both got %s", ua.HomeDir)
	}

	// Drop a marker file in A's home (writing as A's uid).
	marker := filepath.Join(ua.HomeDir, "A-marker")
	if err := os.WriteFile(marker, []byte("a"), 0644); err != nil {
		t.Fatalf("write A marker: %v", err)
	}
	if _, err := os.Stat(filepath.Join(ub.HomeDir, "A-marker")); err == nil {
		t.Errorf("A's marker visible in B's home — homes are not isolated")
	}

	// Destroy A; B's state must survive untouched.
	if err := mgr.DestroySandboxUser(&SandboxUserPayload{Name: a}); err != nil {
		t.Fatalf("destroy a: %v", err)
	}
	if _, err := user.Lookup("sb-" + b); err != nil {
		t.Errorf("destroying A took out B: %v", err)
	}
	if _, err := os.Stat(ub.HomeDir); err != nil {
		t.Errorf("B's home gone after destroying A: %v", err)
	}
	if _, err := os.Stat("/run/netns/" + b); err != nil {
		t.Errorf("B's netns gone after destroying A: %v", err)
	}
}

// User has written real files into their home. Destroy must remove
// everything; the symlinks-to-HM-gen don't dereference and wipe the HM
// source.
func TestDestroyRemovesUserWrites(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}

	hmDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hmDir, ".zshrc"), []byte("# fake hm"), 0644); err != nil {
		t.Fatal(err)
	}

	name := "iso-writes"
	mgr := NewUserManager(hmDir)
	_ = mgr.DestroySandboxUser(&SandboxUserPayload{Name: name})
	t.Cleanup(func() { cleanupSandbox(t, name) })

	if err := mgr.CreateSandboxUser(&SandboxUserPayload{Name: name}); err != nil {
		t.Fatalf("create: %v", err)
	}

	home := "/home/sb-" + name
	// Add some user data (deeper than top level).
	if err := os.MkdirAll(filepath.Join(home, "work", "subdir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "work", "subdir", "data.txt"), []byte("user data"), 0644); err != nil {
		t.Fatal(err)
	}

	if err := mgr.DestroySandboxUser(&SandboxUserPayload{Name: name}); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := os.Stat(home); err == nil {
		t.Errorf("home %s still present after destroy", home)
	}

	// The HM gen must be intact — symlinks shouldn't have caused
	// dereferenced deletion.
	if _, err := os.Stat(filepath.Join(hmDir, ".zshrc")); err != nil {
		t.Errorf("HM gen .zshrc was nuked by destroy: %v", err)
	}
}

// Realistic teardown scenario: bindfs is mounted under the sb home
// (this is what mb does — bindfs source → /home/sb-<name>/workspace).
// Destroy must umount before userdel, otherwise userdel -r fails or
// (worse) deletes through the mount.
func TestDestroyWithBindfsMountedUnderHome(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}
	// sudo strips PATH; check the well-known spots, then fall back to
	// scanning /nix/store for the bindfs we know stereosd uses.
	bindfs := ""
	for _, candidate := range []string{
		"bindfs",
		"/run/current-system/sw/bin/bindfs",
	} {
		if path, err := exec.LookPath(candidate); err == nil {
			bindfs = path
			break
		}
	}
	if bindfs == "" {
		if matches, _ := filepath.Glob("/nix/store/*-bindfs-*/bin/bindfs"); len(matches) > 0 {
			bindfs = matches[0]
		}
	}
	if bindfs == "" {
		t.Skip("bindfs not findable on this host")
	}

	name := "iso-bindfs"
	mgr := NewUserManager("")
	_ = mgr.DestroySandboxUser(&SandboxUserPayload{Name: name})
	t.Cleanup(func() { cleanupSandbox(t, name) })

	if err := mgr.CreateSandboxUser(&SandboxUserPayload{Name: name}); err != nil {
		t.Fatalf("create: %v", err)
	}

	u, _ := user.Lookup("sb-" + name)
	workspace := filepath.Join(u.HomeDir, "workspace")
	if err := os.Mkdir(workspace, 0755); err != nil {
		t.Fatal(err)
	}

	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "should-survive.txt"), []byte("host data"), 0644); err != nil {
		t.Fatal(err)
	}

	mount := exec.Command(bindfs, "-o", "allow_other", src, workspace)
	if out, err := mount.CombinedOutput(); err != nil {
		t.Fatalf("bindfs mount: %v: %s", err, out)
	}
	t.Cleanup(func() {
		// Always try to umount, even if the test already did.
		_ = exec.Command("umount", "-l", workspace).Run()
	})

	if err := mgr.DestroySandboxUser(&SandboxUserPayload{Name: name}); err != nil {
		t.Logf("destroy returned (possibly expected) error: %v", err)
	}

	// Did userdel remove the user record?
	if _, err := user.Lookup("sb-" + name); err == nil {
		t.Errorf("user sb-%s still exists after destroy with mounted bindfs", name)
	}

	// CRITICAL: did the destroy preserve src or did it nuke it through the mount?
	if _, err := os.Stat(filepath.Join(src, "should-survive.txt")); err != nil {
		t.Errorf("host data was deleted through bindfs! src lost should-survive.txt: %v", err)
	}

	// Is the mount still there?
	mountList, _ := exec.Command("mount").Output()
	if strings.Contains(string(mountList), workspace+" ") {
		t.Errorf("bindfs at %s is still mounted after destroy", workspace)
	}
}

// Process is running as the sb user when destroy is called. Real
// scenario: agentd or claude-code still alive. userdel will refuse
// while the user has procs.
func TestDestroyWithRunningProcess(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}

	name := "iso-procs"
	mgr := NewUserManager("")
	_ = mgr.DestroySandboxUser(&SandboxUserPayload{Name: name})
	t.Cleanup(func() {
		// Make sure no leftover proc keeps the user undestroyable next run.
		_ = exec.Command("pkill", "-9", "-u", "sb-"+name).Run()
		time.Sleep(100 * time.Millisecond)
		cleanupSandbox(t, name)
	})

	if err := mgr.CreateSandboxUser(&SandboxUserPayload{Name: name}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Launch a long-running process as the sb user.
	u, _ := user.Lookup("sb-" + name)
	cmd := exec.Command("sudo", "-u", "sb-"+name, "sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("spawn proc as user: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// Brief settle so /proc shows the new uid-owned process.
	time.Sleep(200 * time.Millisecond)

	err := mgr.DestroySandboxUser(&SandboxUserPayload{Name: name})
	t.Logf("destroy with running proc as %s (uid=%s): err=%v", u.Username, u.Uid, err)

	// Either Destroy must have killed the proc and removed the user,
	// or it must report a clean error explaining the failure.
	if _, lookupErr := user.Lookup("sb-" + name); lookupErr == nil {
		// User still exists: that's a real teardown gap. The expected
		// behavior is for Destroy to either reap procs first or fail
		// loudly so the caller knows to retry.
		if err == nil {
			t.Errorf("destroy returned nil but user still exists with running proc — silent partial failure")
		} else {
			t.Logf("KNOWN GAP: destroy did not kill running process; reported: %v", err)
		}
	}
}

// Invalid sandbox names must be rejected without touching the system.
func TestInvalidNamesRejected(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}

	mgr := NewUserManager("")
	bad := []string{
		"",
		"UPPERCASE",
		"has space",
		"has/slash",
		"has;semicolon",
		"with$dollar",
		"this-name-is-far-too-long-to-fit-in-the-limit",
	}
	for _, name := range bad {
		err := mgr.CreateSandboxUser(&SandboxUserPayload{Name: name})
		if err == nil {
			t.Errorf("expected error for invalid name %q, got nil", name)
			_ = mgr.DestroySandboxUser(&SandboxUserPayload{Name: name})
		}
	}
}

// UIDs increment when consecutive Creates happen.
func TestSequentialUIDAllocation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("must run as root")
	}

	mgr := NewUserManager("")
	names := []string{"iso-uid-a", "iso-uid-b", "iso-uid-c"}
	for _, n := range names {
		_ = mgr.DestroySandboxUser(&SandboxUserPayload{Name: n})
	}
	t.Cleanup(func() {
		for _, n := range names {
			cleanupSandbox(t, n)
		}
	})

	uids := make([]string, 0, len(names))
	for _, n := range names {
		if err := mgr.CreateSandboxUser(&SandboxUserPayload{Name: n}); err != nil {
			t.Fatalf("create %s: %v", n, err)
		}
		u, _ := user.Lookup("sb-" + n)
		uids = append(uids, u.Uid)
	}

	// No duplicates.
	seen := make(map[string]string)
	for i, uid := range uids {
		if prior, ok := seen[uid]; ok {
			t.Errorf("uid %s reused: %s and %s", uid, prior, names[i])
		}
		seen[uid] = names[i]
	}
	t.Logf("allocated UIDs: %s", strings.Join(uids, ", "))
}

// Make goimports / staticcheck happy in case some helpers above
// don't end up referenced after edits.
var _ = fmt.Sprintf

