package firewall

import (
	"fmt"
	"os/exec"
	"strings"
)

const (
	tcpPort = 8080
)

// BlockAll blocks all incoming traffic on all interfaces and ports.
func BlockAll() error {
	cmd := exec.Command("iptables", "-P", "INPUT", "DROP")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set default INPUT policy to DROP: %w", err)
	}

	// Allow loopback interface (important for localhost)
	if err := runIptables("-A", "INPUT", "-i", "lo", "-j", "ACCEPT"); err != nil {
		return err
	}

	// Allow established connections to continue
	if err := runIptables("-A", "INPUT", "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"); err != nil {
		return err
	}

	return nil
}

// AllowPort opens the TCP port (e.g., 8080) for incoming traffic.
func AllowPort(port int) error {
	args := []string{"-I", "INPUT", "-p", "tcp", "--dport", fmt.Sprintf("%d", port), "-j", "ACCEPT"}
	if err := runIptables(args...); err != nil {
		return fmt.Errorf("failed to allow TCP port %d: %w", port, err)
	}
	return nil
}

// Reset restores INPUT policy to ACCEPT and clears added rules.
func Reset() error {
	// Flush all INPUT rules
	if err := runIptables("-F", "INPUT"); err != nil {
		return err
	}
	// Reset default policy to ACCEPT
	cmd := exec.Command("iptables", "-P", "INPUT", "ACCEPT")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reset INPUT policy: %w", err)
	}
	return nil
}

// Helper to run iptables commands
func runIptables(args ...string) error {
	cmd := exec.Command("iptables", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables error: %v, output: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
