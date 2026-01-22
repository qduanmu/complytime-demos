package ampel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMergePolicy_PreservesCELCode verifies that CEL code from existing policy is preserved.
func TestMergePolicy_PreservesCELCode(t *testing.T) {
	existing := AmpelPolicy{
		Name:        "Test Policy",
		Version:     "1.0.0",
		Description: "Original description",
		Rule:        "all(tenets)",
		Tenets: []Tenet{
			{
				ID:          "req-001-plan-001-0",
				Name:        "Original Name",
				Description: "Original description",
				Code:        "// MANUALLY EDITED CEL CODE\nattestation.verified == true",
				Parameters:  map[string]interface{}{"key": "original"},
			},
		},
	}

	generated := AmpelPolicy{
		Name:        "Test Policy",
		Version:     "2.0.0",
		Description: "Updated description",
		Rule:        "all(tenets)",
		Tenets: []Tenet{
			{
				ID:          "req-001-plan-001-0",
				Name:        "Updated Name",
				Description: "Updated description",
				Code:        "attestation.verified == false", // This should NOT be used
				Parameters:  map[string]interface{}{"key": "generated"},
			},
		},
	}

	merged, stats, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify CEL code was preserved
	assert.Equal(t, "// MANUALLY EDITED CEL CODE\nattestation.verified == true", merged.Tenets[0].Code)

	// Verify stats
	assert.Equal(t, 1, stats.TenetsPreserved)
	assert.Equal(t, 0, stats.TenetsAdded)
	assert.Equal(t, 0, stats.TenetsRemoved)
}

// TestMergePolicy_PreservesParameters verifies that parameters from existing policy are preserved.
func TestMergePolicy_PreservesParameters(t *testing.T) {
	existing := AmpelPolicy{
		Name:        "Test Policy",
		Version:     "1.0.0",
		Description: "Description",
		Rule:        "all(tenets)",
		Tenets: []Tenet{
			{
				ID:          "req-001-plan-001-0",
				Name:        "Tenet",
				Code:        "true",
				Parameters: map[string]interface{}{
					"threshold": 95,
					"enabled":   true,
					"custom":    "manual value",
				},
			},
		},
	}

	generated := AmpelPolicy{
		Name:        "Test Policy",
		Version:     "2.0.0",
		Description: "Description",
		Rule:        "all(tenets)",
		Tenets: []Tenet{
			{
				ID:   "req-001-plan-001-0",
				Name: "Tenet",
				Code: "true",
				Parameters: map[string]interface{}{
					"threshold": 50, // Should NOT be used
					"enabled":   false,
				},
			},
		},
	}

	merged, stats, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify parameters were preserved
	assert.Equal(t, 95, merged.Tenets[0].Parameters["threshold"])
	assert.Equal(t, true, merged.Tenets[0].Parameters["enabled"])
	assert.Equal(t, "manual value", merged.Tenets[0].Parameters["custom"])

	// Verify stats
	assert.Equal(t, 1, stats.TenetsPreserved)
}

// TestMergePolicy_UpdatesMetadata verifies that policy-level metadata is updated from generated.
func TestMergePolicy_UpdatesMetadata(t *testing.T) {
	existing := AmpelPolicy{
		Name:        "Old Policy Name",
		Version:     "1.0.0",
		Description: "Old description",
		Metadata: map[string]string{
			"author": "Old Author",
			"id":     "policy-001",
		},
		Imports: []string{"old-import"},
		Rule:    "all(tenets)",
		Tenets: []Tenet{
			{ID: "tenet-1", Name: "Tenet", Code: "true"},
		},
	}

	generated := AmpelPolicy{
		Name:        "New Policy Name",
		Version:     "2.0.0",
		Description: "New description",
		Metadata: map[string]string{
			"author":  "New Author",
			"id":      "policy-001",
			"updated": "2026-01-22",
		},
		Imports: []string{"new-import-1", "new-import-2"},
		Rule:    "any(tenets)",
		Tenets: []Tenet{
			{ID: "tenet-1", Name: "Tenet", Code: "false"},
		},
	}

	merged, _, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify all policy-level fields were updated
	assert.Equal(t, "New Policy Name", merged.Name)
	assert.Equal(t, "2.0.0", merged.Version)
	assert.Equal(t, "New description", merged.Description)
	assert.Equal(t, "any(tenets)", merged.Rule)

	// Verify metadata was updated
	assert.Equal(t, "New Author", merged.Metadata["author"])
	assert.Equal(t, "policy-001", merged.Metadata["id"])
	assert.Equal(t, "2026-01-22", merged.Metadata["updated"])

	// Verify imports were updated
	assert.Equal(t, []string{"new-import-1", "new-import-2"}, merged.Imports)
}

// TestMergePolicy_UpdatesTenetNames verifies that tenet names/descriptions are updated.
func TestMergePolicy_UpdatesTenetNames(t *testing.T) {
	existing := AmpelPolicy{
		Name:    "Policy",
		Version: "1.0.0",
		Rule:    "all(tenets)",
		Tenets: []Tenet{
			{
				ID:               "tenet-1",
				Name:             "Old Tenet Name",
				Description:      "Old description",
				Code:             "manual.code == true",
				AttestationTypes: []string{"old-type"},
			},
		},
	}

	generated := AmpelPolicy{
		Name:    "Policy",
		Version: "2.0.0",
		Rule:    "all(tenets)",
		Tenets: []Tenet{
			{
				ID:               "tenet-1",
				Name:             "New Tenet Name",
				Description:      "New description with more details",
				Code:             "generated.code == false",
				AttestationTypes: []string{"new-type-1", "new-type-2"},
			},
		},
	}

	merged, _, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify name and description were updated
	assert.Equal(t, "New Tenet Name", merged.Tenets[0].Name)
	assert.Equal(t, "New description with more details", merged.Tenets[0].Description)

	// Verify attestation types were updated
	assert.Equal(t, []string{"new-type-1", "new-type-2"}, merged.Tenets[0].AttestationTypes)

	// But code was preserved
	assert.Equal(t, "manual.code == true", merged.Tenets[0].Code)
}

// TestMergePolicy_AddsNewTenets verifies that new tenets from generated are added.
func TestMergePolicy_AddsNewTenets(t *testing.T) {
	existing := AmpelPolicy{
		Name:    "Policy",
		Version: "1.0.0",
		Rule:    "all(tenets)",
		Tenets: []Tenet{
			{ID: "tenet-1", Name: "Existing Tenet", Code: "existing.code"},
		},
	}

	generated := AmpelPolicy{
		Name:    "Policy",
		Version: "2.0.0",
		Rule:    "all(tenets)",
		Tenets: []Tenet{
			{ID: "tenet-1", Name: "Existing Tenet", Code: "new.code"},
			{ID: "tenet-2", Name: "New Tenet 2", Code: "tenet2.code"},
			{ID: "tenet-3", Name: "New Tenet 3", Code: "tenet3.code"},
		},
	}

	merged, stats, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify all tenets are present
	assert.Equal(t, 3, len(merged.Tenets))

	// Verify stats
	assert.Equal(t, 1, stats.TenetsPreserved)
	assert.Equal(t, 2, stats.TenetsAdded)
	assert.Equal(t, 0, stats.TenetsRemoved)

	// Verify existing tenet preserved its code
	assert.Equal(t, "existing.code", merged.Tenets[0].Code)

	// Verify new tenets were added with generated code
	assert.Equal(t, "tenet-2", merged.Tenets[1].ID)
	assert.Equal(t, "tenet2.code", merged.Tenets[1].Code)
	assert.Equal(t, "tenet-3", merged.Tenets[2].ID)
	assert.Equal(t, "tenet3.code", merged.Tenets[2].Code)
}

// TestMergePolicy_RemovesOrphanedTenets verifies that orphaned tenets are removed.
func TestMergePolicy_RemovesOrphanedTenets(t *testing.T) {
	existing := AmpelPolicy{
		Name:    "Policy",
		Version: "1.0.0",
		Rule:    "all(tenets)",
		Tenets: []Tenet{
			{ID: "tenet-1", Name: "Tenet 1", Code: "code1"},
			{ID: "tenet-2", Name: "Tenet 2", Code: "code2"},
			{ID: "tenet-3", Name: "Tenet 3", Code: "code3"},
		},
	}

	generated := AmpelPolicy{
		Name:    "Policy",
		Version: "2.0.0",
		Rule:    "all(tenets)",
		Tenets: []Tenet{
			{ID: "tenet-1", Name: "Tenet 1", Code: "newcode1"},
			// tenet-2 and tenet-3 are not in generated (orphaned)
		},
	}

	merged, stats, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify only tenet-1 remains
	assert.Equal(t, 1, len(merged.Tenets))
	assert.Equal(t, "tenet-1", merged.Tenets[0].ID)

	// Verify stats
	assert.Equal(t, 1, stats.TenetsPreserved)
	assert.Equal(t, 0, stats.TenetsAdded)
	assert.Equal(t, 2, stats.TenetsRemoved)
}

// TestMergePolicy_ValidationFailure verifies that validation errors are caught.
func TestMergePolicy_ValidationFailure(t *testing.T) {
	existing := AmpelPolicy{
		Name:    "Policy",
		Version: "1.0.0",
		Rule:    "all(tenets)",
		Tenets: []Tenet{
			{ID: "tenet-1", Name: "Tenet", Code: "code"},
		},
	}

	// Generated policy with invalid tenet (missing required fields)
	generated := AmpelPolicy{
		Name:    "Policy",
		Version: "2.0.0",
		Rule:    "all(tenets)",
		Tenets: []Tenet{
			{ID: "tenet-1", Name: "", Code: ""}, // Invalid: missing name and code
		},
	}

	_, _, err := MergePolicy(existing, generated)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation failed")
}

// TestMergePolicy_EmptyExisting verifies merging with empty existing policy.
func TestMergePolicy_EmptyExisting(t *testing.T) {
	existing := AmpelPolicy{
		Name:    "Policy",
		Version: "1.0.0",
		Rule:    "all(tenets)",
		Tenets:  []Tenet{}, // No existing tenets
	}

	generated := AmpelPolicy{
		Name:    "Policy",
		Version: "2.0.0",
		Rule:    "all(tenets)",
		Tenets: []Tenet{
			{ID: "tenet-1", Name: "Tenet 1", Code: "code1"},
			{ID: "tenet-2", Name: "Tenet 2", Code: "code2"},
		},
	}

	merged, stats, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// All tenets should be added
	assert.Equal(t, 2, len(merged.Tenets))
	assert.Equal(t, 0, stats.TenetsPreserved)
	assert.Equal(t, 2, stats.TenetsAdded)
	assert.Equal(t, 0, stats.TenetsRemoved)
}

// TestMergePolicy_ComplexScenario tests a complex merge with multiple changes.
func TestMergePolicy_ComplexScenario(t *testing.T) {
	existing := AmpelPolicy{
		Name:    "Complex Policy",
		Version: "1.0.0",
		Rule:    "all(tenets)",
		Tenets: []Tenet{
			{ID: "tenet-1", Name: "Keep", Code: "manual1", Parameters: map[string]interface{}{"p1": 1}},
			{ID: "tenet-2", Name: "Remove", Code: "manual2"},
			{ID: "tenet-3", Name: "Update", Code: "manual3", Parameters: map[string]interface{}{"p3": 3}},
		},
	}

	generated := AmpelPolicy{
		Name:    "Complex Policy",
		Version: "2.0.0",
		Rule:    "any(tenets)",
		Tenets: []Tenet{
			{ID: "tenet-1", Name: "Keep Updated", Code: "gen1", Parameters: map[string]interface{}{"p1": 999}},
			{ID: "tenet-3", Name: "Update Updated", Code: "gen3", Parameters: map[string]interface{}{"p3": 999}},
			{ID: "tenet-4", Name: "Add", Code: "gen4"},
		},
	}

	merged, stats, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify correct tenets
	assert.Equal(t, 3, len(merged.Tenets))

	// Verify tenet-1 (preserved)
	assert.Equal(t, "tenet-1", merged.Tenets[0].ID)
	assert.Equal(t, "Keep Updated", merged.Tenets[0].Name)
	assert.Equal(t, "manual1", merged.Tenets[0].Code) // Preserved
	assert.Equal(t, 1, merged.Tenets[0].Parameters["p1"]) // Preserved

	// Verify tenet-3 (preserved)
	assert.Equal(t, "tenet-3", merged.Tenets[1].ID)
	assert.Equal(t, "Update Updated", merged.Tenets[1].Name)
	assert.Equal(t, "manual3", merged.Tenets[1].Code) // Preserved
	assert.Equal(t, 3, merged.Tenets[1].Parameters["p3"]) // Preserved

	// Verify tenet-4 (added)
	assert.Equal(t, "tenet-4", merged.Tenets[2].ID)
	assert.Equal(t, "Add", merged.Tenets[2].Name)
	assert.Equal(t, "gen4", merged.Tenets[2].Code)

	// Verify stats
	assert.Equal(t, 2, stats.TenetsPreserved)
	assert.Equal(t, 1, stats.TenetsAdded)
	assert.Equal(t, 1, stats.TenetsRemoved)

	// Verify policy-level fields updated
	assert.Equal(t, "2.0.0", merged.Version)
	assert.Equal(t, "any(tenets)", merged.Rule)
}
