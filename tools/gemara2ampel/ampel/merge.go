package ampel

import "fmt"

// MergeStats contains statistics about a policy merge operation.
type MergeStats struct {
	TenetsPreserved int // Existing tenets with preserved code/params
	TenetsAdded     int // New tenets from Gemara
	TenetsRemoved   int // Orphaned tenets deleted
}

// MergePolicy merges a generated policy with an existing policy, preserving manual edits
// to CEL code and parameters while updating metadata and other fields from the generated policy.
//
// The merge algorithm:
// 1. Updates all policy-level fields (name, version, description, metadata, imports, rule) from generated
// 2. For each tenet in the generated policy:
//    - If a matching tenet exists in the existing policy (by ID), preserve its code and parameters
//    - If no match exists, add the new tenet from generated
// 3. Remove any tenets in existing that are not in generated (orphaned)
// 4. Validate the merged policy
//
// Returns the merged policy, merge statistics, and any validation error.
func MergePolicy(existing, generated AmpelPolicy) (AmpelPolicy, MergeStats, error) {
	stats := MergeStats{}

	// Start with the generated policy as the base (updates all metadata)
	merged := AmpelPolicy{
		Name:        generated.Name,
		Description: generated.Description,
		Version:     generated.Version,
		Metadata:    generated.Metadata,
		Imports:     generated.Imports,
		Rule:        generated.Rule,
		Tenets:      make([]Tenet, 0, len(generated.Tenets)),
	}

	// Build map of existing tenets by ID for fast lookup
	existingTenets := make(map[string]Tenet)
	for _, tenet := range existing.Tenets {
		existingTenets[tenet.ID] = tenet
	}

	// Process each tenet in the generated policy
	for _, generatedTenet := range generated.Tenets {
		if existingTenet, found := existingTenets[generatedTenet.ID]; found {
			// Tenet exists - merge it (preserve code and parameters)
			mergedTenet := mergeTenet(existingTenet, generatedTenet)
			merged.Tenets = append(merged.Tenets, mergedTenet)
			stats.TenetsPreserved++
		} else {
			// New tenet - add it from generated
			merged.Tenets = append(merged.Tenets, generatedTenet)
			stats.TenetsAdded++
		}
	}

	// Calculate removed tenets (in existing but not in generated)
	generatedTenetIDs := make(map[string]bool)
	for _, tenet := range generated.Tenets {
		generatedTenetIDs[tenet.ID] = true
	}
	for id := range existingTenets {
		if !generatedTenetIDs[id] {
			stats.TenetsRemoved++
		}
	}

	// Validate the merged policy
	if err := merged.Validate(); err != nil {
		return AmpelPolicy{}, stats, fmt.Errorf("merged policy validation failed: %w", err)
	}

	return merged, stats, nil
}

// mergeTenet merges a single tenet, preserving code and parameters from existing
// while updating other fields from generated.
func mergeTenet(existing, generated Tenet) Tenet {
	return Tenet{
		ID:               generated.ID, // Use generated (should be same)
		Name:             generated.Name,
		Description:      generated.Description,
		Code:             existing.Code,       // PRESERVE manual CEL edits
		AttestationTypes: generated.AttestationTypes,
		Parameters:       existing.Parameters, // PRESERVE manual parameter edits
	}
}
