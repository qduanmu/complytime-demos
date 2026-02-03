package ampel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Workspace manages Ampel policy files in a directory.
type Workspace struct {
	Path string
}

// NewWorkspace creates or opens a workspace at the specified path.
// The directory is created automatically if it doesn't exist.
func NewWorkspace(path string) (*Workspace, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workspace directory: %w", err)
	}

	return &Workspace{Path: path}, nil
}

// LoadPolicy loads an existing Ampel policy from the workspace.
// Returns an error if the policy file doesn't exist or cannot be parsed.
func (w *Workspace) LoadPolicy(policyID string) (*Policy, error) {
	policyPath := w.GetPolicyPath(policyID)

	data, err := os.ReadFile(policyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("policy file not found: %s", policyPath)
		}
		return nil, fmt.Errorf("failed to read policy file: %w", err)
	}

	var policy Policy
	if err := json.Unmarshal(data, &policy); err != nil {
		return nil, fmt.Errorf("failed to parse policy JSON (try -force-overwrite to regenerate): %w", err)
	}

	return &policy, nil
}

// SavePolicy saves an Ampel policy to the workspace.
// The policy is written with proper JSON formatting and secure file permissions.
func (w *Workspace) SavePolicy(policyID string, policy *Policy) error {
	policyPath := w.GetPolicyPath(policyID)

	// Serialize to JSON using protobuf JSON marshaling
	data, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize policy: %w", err)
	}

	// Write to file with secure permissions (read/write for owner only)
	if err := os.WriteFile(policyPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write policy file %s: %w", policyPath, err)
	}

	return nil
}

// PolicyExists checks if a policy file exists in the workspace.
func (w *Workspace) PolicyExists(policyID string) bool {
	policyPath := w.GetPolicyPath(policyID)
	_, err := os.Stat(policyPath)
	return err == nil
}

// GetPolicyPath returns the full file path for a policy ID.
// The policy ID is sanitized to create a safe filename.
func (w *Workspace) GetPolicyPath(policyID string) string {
	filename := sanitizePolicyID(policyID) + ".json"
	return filepath.Join(w.Path, filename)
}

// sanitizePolicyID converts a policy ID to a safe filename by replacing
// problematic characters with hyphens.
func sanitizePolicyID(policyID string) string {
	// Replace path separators and other problematic characters
	sanitized := strings.ReplaceAll(policyID, "/", "-")
	sanitized = strings.ReplaceAll(sanitized, "\\", "-")
	sanitized = strings.ReplaceAll(sanitized, ":", "-")
	return sanitized
}
