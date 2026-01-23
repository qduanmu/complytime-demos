package ampel

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewWorkspace_AutoCreate verifies that workspace directory is auto-created.
func TestNewWorkspace_AutoCreate(t *testing.T) {
	// Create temp directory for test
	tempDir := t.TempDir()
	workspacePath := filepath.Join(tempDir, "test-workspace")

	// Workspace should not exist yet
	_, err := os.Stat(workspacePath)
	require.True(t, os.IsNotExist(err))

	// Create workspace
	ws, err := NewWorkspace(workspacePath)
	require.NoError(t, err)
	require.NotNil(t, ws)
	assert.Equal(t, workspacePath, ws.Path)

	// Verify directory was created
	info, err := os.Stat(workspacePath)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

// TestNewWorkspace_ExistingDirectory verifies that existing directories work.
func TestNewWorkspace_ExistingDirectory(t *testing.T) {
	// Create temp directory
	tempDir := t.TempDir()

	// Create workspace using existing directory
	ws, err := NewWorkspace(tempDir)
	require.NoError(t, err)
	require.NotNil(t, ws)
	assert.Equal(t, tempDir, ws.Path)
}

// TestWorkspace_SaveAndLoadPolicy verifies policy save and load roundtrip.
func TestWorkspace_SaveAndLoadPolicy(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	require.NoError(t, err)

	policy := AmpelPolicy{
		Id: "policy-001",
		Meta: &Meta{
			Runtime:     "cel@v14.0",
			Version:     1,
			Description: "Test description",
			AssertMode:  "AND",
		},
		Tenets: []*Tenet{
			{
				Id:      "tenet-1",
				Title:   "Test Tenet",
				Runtime: "cel@v14.0",
				Code:    "attestation.verified == true",
				Predicates: &PredicateSpec{
					Types: []string{"https://example.com/attestation/v1"},
				},
				Outputs: map[string]*Output{
					"threshold": {Code: "context.threshold", Value: 95},
					"enabled":   {Code: "context.enabled", Value: true},
				},
			},
		},
	}

	// Save policy
	policyID := "policy-001"
	err = ws.SavePolicy(policyID, policy)
	require.NoError(t, err)

	// Verify file exists
	assert.True(t, ws.PolicyExists(policyID))

	// Load policy
	loadedPolicy, err := ws.LoadPolicy(policyID)
	require.NoError(t, err)
	require.NotNil(t, loadedPolicy)

	// Verify all fields match
	assert.Equal(t, policy.Id, loadedPolicy.Id)
	assert.Equal(t, policy.Meta.Version, loadedPolicy.Meta.Version)
	assert.Equal(t, policy.Meta.Description, loadedPolicy.Meta.Description)
	assert.Equal(t, policy.Meta.AssertMode, loadedPolicy.Meta.AssertMode)
	assert.Equal(t, len(policy.Tenets), len(loadedPolicy.Tenets))

	// Verify tenet fields
	assert.Equal(t, policy.Tenets[0].Id, loadedPolicy.Tenets[0].Id)
	assert.Equal(t, policy.Tenets[0].Title, loadedPolicy.Tenets[0].Title)
	assert.Equal(t, policy.Tenets[0].Code, loadedPolicy.Tenets[0].Code)

	// Verify outputs - JSON unmarshaling converts numbers to float64
	assert.Equal(t, float64(95), loadedPolicy.Tenets[0].Outputs["threshold"].Value)
	assert.Equal(t, true, loadedPolicy.Tenets[0].Outputs["enabled"].Value)
}

// TestWorkspace_LoadPolicy_NotFound verifies error when policy doesn't exist.
func TestWorkspace_LoadPolicy_NotFound(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	require.NoError(t, err)

	// Try to load non-existent policy
	_, err = ws.LoadPolicy("non-existent-policy")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "policy file not found")
}

// TestWorkspace_LoadPolicy_InvalidJSON verifies error handling for corrupt JSON.
func TestWorkspace_LoadPolicy_InvalidJSON(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	require.NoError(t, err)

	// Write invalid JSON to policy file
	policyID := "corrupt-policy"
	policyPath := ws.GetPolicyPath(policyID)
	err = os.WriteFile(policyPath, []byte("{ invalid json }"), 0600)
	require.NoError(t, err)

	// Try to load corrupt policy
	_, err = ws.LoadPolicy(policyID)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse policy JSON")
	assert.Contains(t, err.Error(), "try -force-overwrite")
}

// TestWorkspace_PolicyExists verifies existence check.
func TestWorkspace_PolicyExists(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	require.NoError(t, err)

	policyID := "test-policy"

	// Should not exist initially
	assert.False(t, ws.PolicyExists(policyID))

	policy := AmpelPolicy{
		Id: "test-policy",
		Meta: &Meta{
			AssertMode: "AND",
		},
		Tenets: []*Tenet{
			{
				Id:    "t1",
				Title: "T1",
				Code:  "true",
			},
		},
	}
	err = ws.SavePolicy(policyID, policy)
	require.NoError(t, err)

	// Should exist now
	assert.True(t, ws.PolicyExists(policyID))
}

// TestWorkspace_GetPolicyPath verifies path generation.
func TestWorkspace_GetPolicyPath(t *testing.T) {
	ws, err := NewWorkspace("/tmp/test-workspace")
	require.NoError(t, err)

	tests := []struct {
		name       string
		policyID   string
		wantSuffix string
	}{
		{
			name:       "simple ID",
			policyID:   "policy-001",
			wantSuffix: "policy-001.json",
		},
		{
			name:       "ID with slashes",
			policyID:   "org/team/policy",
			wantSuffix: "org-team-policy.json",
		},
		{
			name:       "ID with backslashes",
			policyID:   "org\\team\\policy",
			wantSuffix: "org-team-policy.json",
		},
		{
			name:       "ID with colons",
			policyID:   "namespace:policy:v1",
			wantSuffix: "namespace-policy-v1.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := ws.GetPolicyPath(tt.policyID)
			assert.Equal(t, filepath.Join("/tmp/test-workspace", tt.wantSuffix), path)
		})
	}
}

// TestSanitizePolicyID verifies filename sanitization.
func TestSanitizePolicyID(t *testing.T) {
	tests := []struct {
		name     string
		policyID string
		want     string
	}{
		{
			name:     "no special chars",
			policyID: "policy-001",
			want:     "policy-001",
		},
		{
			name:     "forward slashes",
			policyID: "org/team/policy",
			want:     "org-team-policy",
		},
		{
			name:     "backslashes",
			policyID: "org\\team\\policy",
			want:     "org-team-policy",
		},
		{
			name:     "colons",
			policyID: "namespace:policy:v1",
			want:     "namespace-policy-v1",
		},
		{
			name:     "mixed special chars",
			policyID: "org/team\\policy:v1",
			want:     "org-team-policy-v1",
		},
		{
			name:     "empty string",
			policyID: "",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizePolicyID(tt.policyID)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestWorkspace_FilePermissions verifies that files are created with secure permissions.
func TestWorkspace_FilePermissions(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	require.NoError(t, err)

	policy := AmpelPolicy{
		Id: "test-policy",
		Meta: &Meta{
			AssertMode: "AND",
		},
		Tenets: []*Tenet{
			{
				Id:    "t1",
				Title: "T1",
				Code:  "true",
			},
		},
	}
	policyID := "test-policy"
	err = ws.SavePolicy(policyID, policy)
	require.NoError(t, err)

	// Check file permissions
	policyPath := ws.GetPolicyPath(policyID)
	info, err := os.Stat(policyPath)
	require.NoError(t, err)

	// File should be readable/writable by owner only (0600)
	mode := info.Mode()
	assert.Equal(t, os.FileMode(0600), mode.Perm())
}

// TestWorkspace_MultiplePolicies verifies managing multiple policies.
func TestWorkspace_MultiplePolicies(t *testing.T) {
	ws, err := NewWorkspace(t.TempDir())
	require.NoError(t, err)

	policies := map[string]AmpelPolicy{
		"policy-001": {
			Id: "policy-001",
			Meta: &Meta{
				AssertMode: "AND",
			},
			Tenets: []*Tenet{
				{
					Id:    "t1",
					Title: "T1",
					Code:  "true",
				},
			},
		},
		"policy-002": {
			Id: "policy-002",
			Meta: &Meta{
				AssertMode: "OR",
			},
			Tenets: []*Tenet{
				{
					Id:    "t2",
					Title: "T2",
					Code:  "false",
				},
			},
		},
		"policy-003": {
			Id: "policy-003",
			Meta: &Meta{
				AssertMode: "AND",
			},
			Tenets: []*Tenet{
				{
					Id:    "t3",
					Title: "T3",
					Code:  "true",
				},
			},
		},
	}

	// Save all policies
	for id, policy := range policies {
		err := ws.SavePolicy(id, policy)
		require.NoError(t, err)
	}

	// Verify all policies exist
	for id := range policies {
		assert.True(t, ws.PolicyExists(id))
	}

	// Load and verify each policy
	for id, originalPolicy := range policies {
		loadedPolicy, err := ws.LoadPolicy(id)
		require.NoError(t, err)
		assert.Equal(t, originalPolicy.Id, loadedPolicy.Id)
		assert.Equal(t, originalPolicy.Meta.AssertMode, loadedPolicy.Meta.AssertMode)
	}
}
