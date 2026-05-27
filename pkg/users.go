// users.go implements per-sandbox system user provisioning. Each sandbox
// gets its own `sb-<name>` user with a dedicated home, login-shell wrapper,
// and network namespace. Provides filesystem-level isolation between
// concurrent sandboxes that previously shared a single `agent` user.
//
// Operations are idempotent: creating an existing user or destroying a
// missing one is not an error. UIDs are allocated from [2000, 2999] by
// scanning /etc/passwd; collisions cause Create to fail.
package stereosd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	sandboxUserPrefix    = "sb-"
	sandboxUIDMin        = 2000
	sandboxUIDMax        = 2999
	sandboxShellDir      = "/run/stereos/shells"
	sandboxNsenterBinary = "/run/wrappers/bin/nsenter-sandbox"
	sandboxLoginShell    = "/bin/bash" // bash --login inside the netns
	// sandboxSharedNetns is the netns name all sb-<name> users currently
	// join. Phase 1 reuses the existing agent-sandbox netns (set up by
	// the agent-netns service with veth + NAT) so sb sandboxes have
	// outbound internet. Phase 2 will give each sandbox its own netns
	// with dedicated veth/NAT; this constant will move to NewUserManager
	// then.
	sandboxSharedNetns = "agent-sandbox"
)

// sandboxNameRe restricts sandbox names to characters safe for both
// usernames and netns names: lowercase alphanumerics plus _ and -.
var sandboxNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,23}$`)

// UserManager provisions and tears down per-sandbox `sb-<name>` users.
//
// hmGenPath, when non-empty, points at a home-manager generation's
// home-files/ directory whose top-level entries are symlinked into each
// new sandbox home. Empty disables the symlink step (useful in tests).
type UserManager struct {
	hmGenPath string
}

// NewUserManager constructs a UserManager. hmGenPath is typically read
// from $STEREOSD_AGENT_HM_GEN, set by the stereos NixOS module so it
// pins the agent-user's home-manager-files store path.
func NewUserManager(hmGenPath string) *UserManager {
	return &UserManager{hmGenPath: hmGenPath}
}

// CreateSandboxUser provisions sb-<name>. Steps, in order:
//  1. Validate the name (regex above).
//  2. Return success if the user already exists (idempotent).
//  3. Allocate the next free UID in [sandboxUIDMin, sandboxUIDMax].
//  4. Write the per-user shell wrapper to /run/stereos/shells/sb-<name>.
//  5. useradd with that shell and a fresh home.
//  6. Create the per-sandbox netns.
//  7. Symlink home-manager top-level entries into the new home.
//
// Any step's failure leaves prior steps in place (no rollback) — the
// next Create call sees the partial state and skips the steps already
// done. Pair with DestroySandboxUser for cleanup on the caller side.
func (m *UserManager) CreateSandboxUser(payload *SandboxUserPayload) error {
	if payload == nil || payload.Name == "" {
		return fmt.Errorf("sandbox name cannot be empty")
	}
	if !sandboxNameRe.MatchString(payload.Name) {
		return fmt.Errorf("invalid sandbox name %q: must match %s", payload.Name, sandboxNameRe.String())
	}

	username := sandboxUserPrefix + payload.Name

	if _, err := user.Lookup(username); err == nil {
		log.Printf("users: %s already exists, no-op", username)
		return nil
	}

	uid, err := allocateSandboxUID()
	if err != nil {
		return fmt.Errorf("allocate uid: %w", err)
	}

	shellPath, err := writeSandboxShell(payload.Name)
	if err != nil {
		return fmt.Errorf("write shell wrapper: %w", err)
	}

	home := "/home/" + username
	cmd := exec.Command(
		"useradd",
		"--system",
		"--create-home",
		"--home-dir", home,
		"--uid", strconv.Itoa(uid),
		"--shell", shellPath,
		"--comment", "stereOS sandbox user for "+payload.Name,
		username,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("useradd %s: %w: %s", username, err, strings.TrimSpace(string(out)))
	}

	// Phase 1 reuses the existing agent-sandbox netns. ensureNetns
	// stays defined for Phase 2 (per-sandbox netns + veth/NAT) but is
	// not called here.

	if m.hmGenPath != "" {
		if err := symlinkHomeManagerTree(m.hmGenPath, home, uid); err != nil {
			return fmt.Errorf("symlink home-manager tree: %w", err)
		}
	}

	log.Printf("users: provisioned %s (uid=%d, home=%s, shell=%s)", username, uid, home, shellPath)
	return nil
}

// DestroySandboxUser tears down sb-<name>. Idempotent: missing user is
// a no-op. Steps continue past individual failures so a half-broken
// instance can still be cleaned up; the first error encountered is
// returned at the end.
//
// Order matters:
//  1. SIGKILL any processes still running as the user (otherwise
//     userdel refuses with "user is currently used by process").
//     Realistic case: agentd / claude-code / a stray SSH session.
//  2. Unmount everything mounted under /home/<user>. Necessary for
//     bindfs mounts that mb didn't tear down via MsgUnmount, and to
//     avoid userdel -r deleting files THROUGH the mount into the
//     host source.
//  3. userdel --remove (removes /etc/passwd entry + home).
//  4. ip netns del.
//  5. Remove the per-sandbox shell wrapper.
func (m *UserManager) DestroySandboxUser(payload *SandboxUserPayload) error {
	if payload == nil || payload.Name == "" {
		return fmt.Errorf("sandbox name cannot be empty")
	}
	if !sandboxNameRe.MatchString(payload.Name) {
		return fmt.Errorf("invalid sandbox name %q", payload.Name)
	}

	username := sandboxUserPrefix + payload.Name
	home := "/home/" + username
	var firstErr error

	// 1. Kill any processes still owned by the user. pkill returns 1
	// when there are no matching processes — that's fine.
	if _, err := user.Lookup(username); err == nil {
		killUserProcesses(username)
	}

	// 2. Unmount anything still mounted at or under the home dir.
	// Defensive — mb should have unmounted shared mounts via
	// MsgUnmount, but a hung mb or a partial up can leave leftovers.
	if _, err := os.Stat(home); err == nil {
		unmountAllUnder(home)
	}

	// 3. userdel --remove.
	if _, err := user.Lookup(username); err == nil {
		cmd := exec.Command("userdel", "--remove", username)
		if out, err := cmd.CombinedOutput(); err != nil {
			firstErr = fmt.Errorf("userdel %s: %w: %s", username, err, strings.TrimSpace(string(out)))
		}
	}

	// 4. netns — Phase 1 shares the agent-sandbox netns owned by the
	// agent-netns systemd service, so there's nothing per-sandbox to
	// destroy here. Reinstate per-sandbox netns deletion in Phase 2.

	// 5. Shell wrapper.
	shellPath := filepath.Join(sandboxShellDir, "sb-"+payload.Name)
	if err := os.Remove(shellPath); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = fmt.Errorf("remove shell wrapper %s: %w", shellPath, err)
	}

	if firstErr == nil {
		log.Printf("users: destroyed %s", username)
	}
	return firstErr
}

// killUserProcesses sends SIGKILL to every process owned by username.
// Loops a few times because new procs can be spawned between the kill
// and userdel (e.g. a parent process respawning a child); bails out
// when no procs are left or after the deadline.
func killUserProcesses(username string) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// pgrep exits 0 if any procs match, 1 if none.
		if err := exec.Command("pgrep", "-u", username).Run(); err != nil {
			return // no procs left
		}
		_ = exec.Command("pkill", "-9", "-u", username).Run()
		time.Sleep(100 * time.Millisecond)
	}
}

// unmountAllUnder lazy-umounts every mountpoint at or under dir.
// Lazy (-l) so an in-use mount detaches immediately and cleans up
// once the last fd is closed — matches what we'd do manually.
//
// Iterates /proc/self/mounts because `mount` is a shell-out and may
// not be on PATH inside stripped systemd unit environments.
func unmountAllUnder(dir string) {
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return
	}

	// Walk top-down so deeper mounts get popped first. /proc/self/mounts
	// is in mount-order; build a list and reverse for safety.
	var targets []string
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		target := fields[1]
		if target == dir || strings.HasPrefix(target, dir+"/") {
			targets = append(targets, target)
		}
	}
	for i := len(targets) - 1; i >= 0; i-- {
		_ = exec.Command("umount", "-l", targets[i]).Run()
	}
}

// allocateSandboxUID scans /etc/passwd for existing sb-* users and
// returns the first free UID in the sandbox range. Fails if every UID
// in the range is taken (which would mean ~1000 concurrent sandboxes).
func allocateSandboxUID() (int, error) {
	taken := make(map[int]bool)

	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return 0, fmt.Errorf("read /etc/passwd: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		if uid >= sandboxUIDMin && uid <= sandboxUIDMax {
			taken[uid] = true
		}
	}

	for uid := sandboxUIDMin; uid <= sandboxUIDMax; uid++ {
		if !taken[uid] {
			return uid, nil
		}
	}
	return 0, fmt.Errorf("no free uid in [%d, %d]", sandboxUIDMin, sandboxUIDMax)
}

// writeSandboxShell renders the per-sandbox shell wrapper and returns
// its path. The wrapper enters the sandbox's network namespace before
// exec'ing bash --login; `mb ssh` layers `cd workdir; exec zsh -l` on
// top to surface direnv/starship hooks.
func writeSandboxShell(name string) (string, error) {
	if err := os.MkdirAll(sandboxShellDir, 0755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", sandboxShellDir, err)
	}

	path := filepath.Join(sandboxShellDir, "sb-"+name)
	content := fmt.Sprintf(`#!%s
if [ -e /run/netns/%s ]; then
  exec %s --net=/run/netns/%s --no-fork %s --login "$@"
else
  exec %s --login "$@"
fi
`, sandboxLoginShell, sandboxSharedNetns, sandboxNsenterBinary, sandboxSharedNetns, sandboxLoginShell, sandboxLoginShell)

	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		return "", fmt.Errorf("write %s: %w", path, err)
	}
	return path, nil
}

// ensureNetns creates /run/netns/<name> if it doesn't exist. Idempotent.
func ensureNetns(name string) error {
	if _, err := os.Stat("/run/netns/" + name); err == nil {
		return nil
	}
	cmd := exec.Command("ip", "netns", "add", name)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("ip netns add %s: %w: %s", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// symlinkHomeManagerTree symlinks the top-level entries of srcDir into
// dstHome, chowned to uid:uid (sb users are in a per-user group that
// shares the uid). Skips entries that already exist in dstHome — useful
// when useradd populated /etc/skel-style defaults that we want to keep.
//
// Goes one level deep: .zshrc and .config become symlinks; the agent
// can still write under .config/foo by creating real files there
// (symlinks dereference, so a write to .config/<existing-dir>/x lands
// in the HM gen — read-only — and fails. Most HM-managed config dirs
// are themselves symlinks-of-symlinks built around individual files,
// so writes outside HM's tracked files succeed.) Deeper handling can
// be added later if real-world apps hit limitations.
func symlinkHomeManagerTree(srcDir, dstHome string, uid int) error {
	entries, err := os.ReadDir(srcDir)
	if err != nil {
		return fmt.Errorf("read %s: %w", srcDir, err)
	}

	for _, entry := range entries {
		src := filepath.Join(srcDir, entry.Name())
		dst := filepath.Join(dstHome, entry.Name())

		if _, err := os.Lstat(dst); err == nil {
			continue
		}

		if err := os.Symlink(src, dst); err != nil {
			return fmt.Errorf("symlink %s -> %s: %w", dst, src, err)
		}
		if err := os.Lchown(dst, uid, uid); err != nil {
			return fmt.Errorf("lchown %s: %w", dst, err)
		}
	}
	return nil
}
