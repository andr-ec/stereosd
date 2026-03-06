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
	"syscall"
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

	if m.FSType == "bind" {
		// Use bindfs (FUSE) for transparent UID/GID mapping between
		// host user and agent. All files appear owned by agent inside
		// the mount, and new files created by agent are stored with
		// the host user's UID/GID on the underlying filesystem.
		info, err := os.Stat(m.Tag)
		if err != nil {
			return fmt.Errorf("stat source %q: %w", m.Tag, err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("cannot determine owner of %q", m.Tag)
		}

		args := []string{
			"--force-user=agent",
			"--force-group=agent",
		}
		if !m.ReadOnly {
			args = append(args,
				fmt.Sprintf("--create-for-user=%d", stat.Uid),
				fmt.Sprintf("--create-for-group=%d", stat.Gid),
			)
		}
		fuseOpts := "allow_other"
		if m.ReadOnly {
			fuseOpts += ",ro"
		}
		args = append(args, "-o", fuseOpts, m.Tag, guestPath)

		log.Printf("mounts: bindfs mounting %s at %s (host uid=%d gid=%d)", m.Tag, guestPath, stat.Uid, stat.Gid)
		if err := mm.commander.Run("bindfs", args...); err != nil {
			return fmt.Errorf("bindfs mount %s at %s: %w", m.Tag, guestPath, err)
		}
	} else {
		// virtiofs / 9p: Tag is the device tag
		var opts []string
		if m.FSType == "9p" {
			opts = append(opts, "trans=virtio,version=9p2000.L")
		}
		if m.ReadOnly {
			opts = append(opts, "ro")
		}
		args := []string{"-t", m.FSType}
		if len(opts) > 0 {
			args = append(args, "-o", strings.Join(opts, ","))
		}
		args = append(args, m.Tag, guestPath)

		log.Printf("mounts: mounting %s (%s) at %s", m.Tag, m.FSType, guestPath)
		if err := mm.commander.Run("mount", args...); err != nil {
			return fmt.Errorf("mount %s at %s: %w", m.Tag, guestPath, err)
		}
		// Set ownership to agent user
		mm.commander.Run("chown", "agent:agent", guestPath)
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
