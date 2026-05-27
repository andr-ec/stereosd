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
)

const (
	sandboxUserPrefix    = "sb-"
	sandboxUIDMin        = 2000
	sandboxUIDMax        = 2999
	sandboxShellDir      = "/run/stereos/shells"
	sandboxNsenterBinary = "/run/wrappers/bin/nsenter-sandbox"
	sandboxLoginShell    = "/bin/bash" // bash --login inside the netns
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

	if err := ensureNetns(payload.Name); err != nil {
		return fmt.Errorf("create netns: %w", err)
	}

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
func (m *UserManager) DestroySandboxUser(payload *SandboxUserPayload) error {
	if payload == nil || payload.Name == "" {
		return fmt.Errorf("sandbox name cannot be empty")
	}
	if !sandboxNameRe.MatchString(payload.Name) {
		return fmt.Errorf("invalid sandbox name %q", payload.Name)
	}

	username := sandboxUserPrefix + payload.Name
	var firstErr error

	if _, err := user.Lookup(username); err == nil {
		cmd := exec.Command("userdel", "--remove", username)
		if out, err := cmd.CombinedOutput(); err != nil {
			firstErr = fmt.Errorf("userdel %s: %w: %s", username, err, strings.TrimSpace(string(out)))
		}
	}

	if _, err := os.Stat("/run/netns/" + payload.Name); err == nil {
		cmd := exec.Command("ip", "netns", "del", payload.Name)
		if out, err := cmd.CombinedOutput(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("ip netns del %s: %w: %s", payload.Name, err, strings.TrimSpace(string(out)))
		}
	}

	shellPath := filepath.Join(sandboxShellDir, "sb-"+payload.Name)
	if err := os.Remove(shellPath); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = fmt.Errorf("remove shell wrapper %s: %w", shellPath, err)
	}

	if firstErr == nil {
		log.Printf("users: destroyed %s", username)
	}
	return firstErr
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
`, sandboxLoginShell, name, sandboxNsenterBinary, name, sandboxLoginShell, sandboxLoginShell)

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
