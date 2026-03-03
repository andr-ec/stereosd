// mounts.go implements shared directory mounting for virtio-fs, 9p, and bind shares.
//
// The host defines shared directories in jcard.toml [[shared]] entries.
// When stereosd receives a mount message, it:
//  1. Creates the guest mount point directory if needed
//  2. Calls mount(2) with the appropriate filesystem type and options
//  3. Sets ownership to the agent user
//
// Supported filesystem types:
//   - "virtiofs" — virtio-fs (preferred, better performance)
//   - "9p"       — Plan 9 filesystem (fallback, wider compatibility)
//   - "bind"     — bind mount (native backend, no VM)
package stereosd

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// MountManager handles mounting and unmounting shared directories.
type MountManager struct {
	// mounts tracks active mounts for cleanup during shutdown
	mounts []MountPayload

	// commander abstracts system commands for testing
	commander Commander
}

// Commander abstracts system command execution for testability.
type Commander interface {
	Run(name string, args ...string) error
	Output(name string, args ...string) ([]byte, error)
}

// ExecCommander uses os/exec to run real system commands.
type ExecCommander struct{}

// Run executes a command and returns any error.
func (ExecCommander) Run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Output executes a command and returns its combined output.
func (ExecCommander) Output(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

// NewMountManager creates a new mount manager.
func NewMountManager(commander Commander) *MountManager {
	if commander == nil {
		commander = ExecCommander{}
	}
	return &MountManager{
		commander: commander,
	}
}

// Mount mounts a shared directory based on the mount payload.
func (mm *MountManager) Mount(m *MountPayload) error {
	if m.Tag == "" {
		return fmt.Errorf("mount tag cannot be empty")
	}
	if m.GuestPath == "" {
		return fmt.Errorf("mount guest_path cannot be empty")
	}
	if m.FSType == "" {
		return fmt.Errorf("mount fs_type cannot be empty")
	}

	// Validate filesystem type
	switch m.FSType {
	case "virtiofs", "9p", "bind":
		// OK
	default:
		return fmt.Errorf("unsupported filesystem type: %q (must be virtiofs, 9p, or bind)", m.FSType)
	}

	// Sanitize the guest path — must be absolute
	guestPath := filepath.Clean(m.GuestPath)
	if !filepath.IsAbs(guestPath) {
		return fmt.Errorf("guest_path must be absolute: %q", m.GuestPath)
	}

	// Prevent mounting over critical system directories
	for _, blocked := range []string{"/", "/nix", "/etc", "/bin", "/boot", "/dev", "/proc", "/sys", "/run"} {
		if guestPath == blocked || strings.HasPrefix(guestPath, blocked+"/") {
			return fmt.Errorf("cannot mount over system directory: %q", guestPath)
		}
	}

	// Create mount point directory if needed
	if err := os.MkdirAll(guestPath, 0755); err != nil {
		return fmt.Errorf("create mount point %q: %w", guestPath, err)
	}

	// Build mount command based on filesystem type
	var args []string
	if m.FSType == "bind" {
		// Bind mount: Tag is the source path on the host
		var opts []string
		opts = append(opts, "bind")
		if m.ReadOnly {
			opts = append(opts, "ro")
		}
		args = []string{"--make-private", "-o", strings.Join(opts, ","), m.Tag, guestPath}
	} else {
		// virtiofs / 9p: Tag is the device tag
		var opts []string
		if m.FSType == "9p" {
			opts = append(opts, "trans=virtio,version=9p2000.L")
		}
		if m.ReadOnly {
			opts = append(opts, "ro")
		}
		args = []string{"-t", m.FSType}
		if len(opts) > 0 {
			args = append(args, "-o", strings.Join(opts, ","))
		}
		args = append(args, m.Tag, guestPath)
	}

	log.Printf("mounts: mounting %s (%s) at %s", m.Tag, m.FSType, guestPath)

	if err := mm.commander.Run("mount", args...); err != nil {
		return fmt.Errorf("mount %s at %s: %w", m.Tag, guestPath, err)
	}

	// Set ownership to agent user (best effort — the user may not exist
	// if this is called very early, but systemd-tmpfiles should have
	// already created the user).
	mm.commander.Run("chown", "agent:agent", guestPath)

	// For bind mounts, the contents are still owned by the host user.
	// Set recursive POSIX ACLs so the agent user can read/write files
	// without changing the original ownership.
	// Only set ACLs on existing files (-Rm), NOT default ACLs (-Rdm).
	// Default ACLs cause new directories to inherit ACL entries, which
	// breaks tools like PostgreSQL that require exact 0700 permissions.
	// New files created by the agent are already owned by agent.
	if m.FSType == "bind" && !m.ReadOnly {
		if err := mm.commander.Run("setfacl", "-Rm", "u:agent:rwX", guestPath); err != nil {
			log.Printf("mounts: warning: failed to set ACLs on %s: %v", guestPath, err)
		}
	}

	// Track the mount for cleanup
	mm.mounts = append(mm.mounts, *m)

	log.Printf("mounts: successfully mounted %s at %s", m.Tag, guestPath)
	return nil
}

// UnmountAll unmounts all tracked shared directories in reverse order.
func (mm *MountManager) UnmountAll() {
	for i := len(mm.mounts) - 1; i >= 0; i-- {
		m := mm.mounts[i]
		guestPath := filepath.Clean(m.GuestPath)
		log.Printf("mounts: unmounting %s", guestPath)

		if err := mm.commander.Run("umount", guestPath); err != nil {
			log.Printf("mounts: warning: failed to unmount %s: %v", guestPath, err)
		}
	}
	mm.mounts = nil
}

// ActiveMounts returns a copy of the currently active mount list.
func (mm *MountManager) ActiveMounts() []MountPayload {
	result := make([]MountPayload, len(mm.mounts))
	copy(result, mm.mounts)
	return result
}
