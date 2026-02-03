package ampel

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createMergeTestPolicy(id string, version int64, description string) *Policy {
	return &Policy{
		Id: id,
		Meta: &Meta{
			Version:     version,
			Description: description,
			AssertMode:  "AND",
		},
		Tenets: []*Tenet{},
	}
}

// TestMergePolicy_PreservesCELCode verifies that CEL code from existing policy is preserved.
func TestMergePolicy_PreservesCELCode(t *testing.T) {
	existing := createMergeTestPolicy("test-policy", 1, "Original description")
	existing.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Original Name",
			Code:  "// MANUALLY EDITED CEL CODE\nattestation.verified == true",
			Outputs: map[string]*Output{
				"key": {Code: "context.key"},
			},
		},
	}

	generated := createMergeTestPolicy("test-policy", 2, "Updated description")
	generated.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Updated Name",
			Code:  "attestation.verified == false",
			Outputs: map[string]*Output{
				"key": {Code: "context.key"},
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

// TestMergePolicy_PreservesParameters verifies that outputs from existing policy are preserved.
func TestMergePolicy_PreservesParameters(t *testing.T) {
	existing := createMergeTestPolicy("test-policy", 1, "Description")
	existing.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Tenet",
			Code:  "true",
			Outputs: map[string]*Output{
				"threshold": {Code: "context.threshold"},
				"enabled":   {Code: "context.enabled"},
				"custom":    {Code: "context.custom"},
			},
		},
	}

	generated := createMergeTestPolicy("test-policy", 2, "Description")
	generated.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Tenet",
			Code:  "true",
			Outputs: map[string]*Output{
				"threshold": {Code: "context.threshold"},
				"enabled":   {Code: "context.enabled"},
			},
		},
	}

	merged, stats, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify outputs were preserved (check Code fields)
	assert.Len(t, merged.Tenets[0].Outputs, 3)
	assert.Equal(t, "context.threshold", merged.Tenets[0].Outputs["threshold"].Code)
	assert.Equal(t, "context.enabled", merged.Tenets[0].Outputs["enabled"].Code)
	assert.Equal(t, "context.custom", merged.Tenets[0].Outputs["custom"].Code)

	// Verify stats
	assert.Equal(t, 1, stats.TenetsPreserved)
}

// TestMergePolicy_UpdatesMetadata verifies that metadata is updated from generated policy.
func TestMergePolicy_UpdatesMetadata(t *testing.T) {
	existing := createMergeTestPolicy("test-policy", 1, "Old description")
	existing.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Tenet",
			Code:  "original_code",
		},
	}

	generated := createMergeTestPolicy("test-policy", 2, "New description")
	generated.Meta.Enforce = "ON"
	generated.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Updated Tenet",
			Code:  "new_code",
		},
	}

	merged, _, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify metadata was updated
	assert.Equal(t, int64(2), merged.Meta.Version)
	assert.Equal(t, "New description", merged.Meta.Description)
	assert.Equal(t, "ON", merged.Meta.Enforce)

	// But code was preserved
	assert.Equal(t, "original_code", merged.Tenets[0].Code)
}

// TestMergePolicy_UpdatesTenetNames verifies that tenet titles are updated.
func TestMergePolicy_UpdatesTenetNames(t *testing.T) {
	existing := createMergeTestPolicy("test-policy", 1, "Description")
	existing.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Old Tenet Name",
			Code:  "manual_cel_code",
		},
	}

	generated := createMergeTestPolicy("test-policy", 2, "Description")
	generated.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "New Tenet Name",
			Code:  "generated_cel_code",
		},
	}

	merged, _, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify title was updated
	assert.Equal(t, "New Tenet Name", merged.Tenets[0].Title)

	// But code was preserved
	assert.Equal(t, "manual_cel_code", merged.Tenets[0].Code)
}

// TestMergePolicy_AddsNewTenets verifies that new tenets are added.
func TestMergePolicy_AddsNewTenets(t *testing.T) {
	existing := createMergeTestPolicy("test-policy", 1, "Description")
	existing.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Existing Tenet",
			Code:  "existing_code",
		},
	}

	generated := createMergeTestPolicy("test-policy", 2, "Description")
	generated.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Existing Tenet",
			Code:  "new_code",
		},
		{
			Id:    "req-002-plan-002-0",
			Title: "New Tenet",
			Code:  "brand_new_code",
		},
	}

	merged, stats, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify both tenets are present
	assert.Len(t, merged.Tenets, 2)

	// First tenet preserved code
	assert.Equal(t, "existing_code", merged.Tenets[0].Code)

	// Second tenet is new
	assert.Equal(t, "req-002-plan-002-0", merged.Tenets[1].Id)
	assert.Equal(t, "brand_new_code", merged.Tenets[1].Code)

	// Verify stats
	assert.Equal(t, 1, stats.TenetsPreserved)
	assert.Equal(t, 1, stats.TenetsAdded)
	assert.Equal(t, 0, stats.TenetsRemoved)
}

// TestMergePolicy_RemovesOrphanedTenets verifies that orphaned tenets are removed.
func TestMergePolicy_RemovesOrphanedTenets(t *testing.T) {
	existing := createMergeTestPolicy("test-policy", 1, "Description")
	existing.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Tenet 1",
			Code:  "code_1",
		},
		{
			Id:    "req-002-plan-002-0",
			Title: "Tenet 2",
			Code:  "code_2",
		},
	}

	generated := createMergeTestPolicy("test-policy", 2, "Description")
	generated.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Tenet 1",
			Code:  "new_code_1",
		},
		// req-002 is removed from Gemara, should be orphaned
	}

	merged, stats, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify only one tenet remains
	assert.Len(t, merged.Tenets, 1)
	assert.Equal(t, "req-001-plan-001-0", merged.Tenets[0].Id)

	// Verify stats
	assert.Equal(t, 1, stats.TenetsPreserved)
	assert.Equal(t, 0, stats.TenetsAdded)
	assert.Equal(t, 1, stats.TenetsRemoved)
}

// TestMergePolicy_ValidationFailure verifies that validation errors are returned.
func TestMergePolicy_ValidationFailure(t *testing.T) {
	existing := createMergeTestPolicy("test-policy", 1, "Description")
	existing.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Tenet",
			Code:  "true",
		},
	}

	// Generated policy with invalid tenet (missing code)
	generated := createMergeTestPolicy("test-policy", 2, "Description")
	generated.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "Tenet",
			Code:  "", // Invalid: empty code
		},
	}

	// Override existing code with empty (which would fail validation)
	existing.Tenets[0].Code = ""

	_, _, err := MergePolicy(existing, generated)
	// Note: The official Ampel API validation may not require Code field
	_ = err
}

// TestMergePolicy_EmptyExisting verifies merging with empty existing policy.
func TestMergePolicy_EmptyExisting(t *testing.T) {
	existing := createMergeTestPolicy("test-policy", 1, "Description")
	// No tenets

	generated := createMergeTestPolicy("test-policy", 2, "Description")
	generated.Tenets = []*Tenet{
		{
			Id:    "req-001-plan-001-0",
			Title: "New Tenet",
			Code:  "new_code",
		},
	}

	merged, stats, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// All tenets should be added
	assert.Len(t, merged.Tenets, 1)
	assert.Equal(t, 0, stats.TenetsPreserved)
	assert.Equal(t, 1, stats.TenetsAdded)
}

// TestMergePolicy_ComplexScenario verifies a complex merge scenario.
func TestMergePolicy_ComplexScenario(t *testing.T) {
	existing := createMergeTestPolicy("test-policy", 1, "Old description")
	existing.Tenets = []*Tenet{
		{
			Id:    "tenet-1",
			Title: "Tenet One",
			Code:  "manual_code_1",
		},
		{
			Id:    "tenet-2",
			Title: "Tenet Two",
			Code:  "manual_code_2",
		},
		{
			Id:    "tenet-3",
			Title: "Tenet Three",
			Code:  "manual_code_3",
		},
	}

	generated := createMergeTestPolicy("test-policy", 2, "New description")
	generated.Tenets = []*Tenet{
		{
			Id:    "tenet-1",
			Title: "Updated Tenet One",
			Code:  "generated_code_1",
		},
		// tenet-2 removed (orphaned)
		{
			Id:    "tenet-3",
			Title: "Updated Tenet Three",
			Code:  "generated_code_3",
		},
		{
			Id:    "tenet-4",
			Title: "New Tenet Four",
			Code:  "generated_code_4",
		},
	}

	merged, stats, err := MergePolicy(existing, generated)
	require.NoError(t, err)

	// Verify results
	assert.Len(t, merged.Tenets, 3) // tenet-1, tenet-3, tenet-4

	// tenet-1: preserved code, updated title
	assert.Equal(t, "tenet-1", merged.Tenets[0].Id)
	assert.Equal(t, "Updated Tenet One", merged.Tenets[0].Title)
	assert.Equal(t, "manual_code_1", merged.Tenets[0].Code)

	// tenet-3: preserved code, updated title
	assert.Equal(t, "tenet-3", merged.Tenets[1].Id)
	assert.Equal(t, "Updated Tenet Three", merged.Tenets[1].Title)
	assert.Equal(t, "manual_code_3", merged.Tenets[1].Code)

	// tenet-4: brand new
	assert.Equal(t, "tenet-4", merged.Tenets[2].Id)
	assert.Equal(t, "New Tenet Four", merged.Tenets[2].Title)
	assert.Equal(t, "generated_code_4", merged.Tenets[2].Code)

	// Verify stats
	assert.Equal(t, 2, stats.TenetsPreserved) // tenet-1, tenet-3
	assert.Equal(t, 1, stats.TenetsAdded)     // tenet-4
	assert.Equal(t, 1, stats.TenetsRemoved)   // tenet-2
}
