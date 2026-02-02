package ampel

import (
	"strings"

	"github.com/gemaraproj/go-gemara"
)

// AttestationTypeInference analyzes a policy to determine which attestation
// types are required for verification.
type AttestationTypeInference struct {
	// RequiresProvenance indicates SLSA provenance attestations are needed
	RequiresProvenance bool

	// RequiresVulnScan indicates vulnerability scan attestations are needed
	RequiresVulnScan bool

	// CustomTypes lists any custom attestation predicate types detected
	CustomTypes []string
}

// AllTypes returns all inferred attestation types as a list of predicate type URLs.
func (inf *AttestationTypeInference) AllTypes() []string {
	var types []string

	if inf.RequiresProvenance {
		types = append(types, "https://slsa.dev/provenance/v1")
	}
	if inf.RequiresVulnScan {
		types = append(types, "https://in-toto.io/Statement/v0.1")
	}

	types = append(types, inf.CustomTypes...)
	return types
}

// InferAttestationTypes analyzes a Gemara policy to determine what attestation
// types are required based on evidence requirements and assessment plans.
func InferAttestationTypes(policy *gemara.Policy) AttestationTypeInference {
	inf := AttestationTypeInference{}

	// Analyze assessment plans for evidence requirements
	for _, plan := range policy.Adherence.AssessmentPlans {
		if plan.EvidenceRequirements != "" {
			analyzeEvidenceRequirement(plan.EvidenceRequirements, &inf)
		}
	}

	// Analyze evaluation methods for attestation hints
	for _, method := range policy.Adherence.EvaluationMethods {
		if method.Description != "" {
			analyzeEvidenceRequirement(method.Description, &inf)
		}
	}

	return inf
}

// InferAttestationType infers a single attestation predicate type URL from
// an evidence requirement string.
func InferAttestationType(evidenceReq string) string {
	lowerReq := strings.ToLower(evidenceReq)

	// Check for SLSA provenance keywords
	for _, keyword := range []string{"slsa", "provenance", "builder", "build provenance"} {
		if strings.Contains(lowerReq, keyword) {
			return "https://slsa.dev/provenance/v1"
		}
	}

	// Check for vulnerability scan keywords
	for _, keyword := range []string{"vulnerabilit", "cve", "security scan", "vuln scan"} {
		if strings.Contains(lowerReq, keyword) {
			return "https://in-toto.io/Statement/v0.1"
		}
	}

	// Check for in-toto attestation keywords
	if strings.Contains(lowerReq, "in-toto") || strings.Contains(lowerReq, "attestation") {
		return "https://in-toto.io/Statement/v0.1"
	}

	// No specific type detected
	return ""
}

// analyzeEvidenceRequirement updates the inference based on an evidence requirement string.
func analyzeEvidenceRequirement(evidenceReq string, inf *AttestationTypeInference) {
	lowerReq := strings.ToLower(evidenceReq)

	// Check for SLSA provenance
	for _, keyword := range []string{"slsa", "provenance", "builder", "build provenance", "build attestation"} {
		if strings.Contains(lowerReq, keyword) {
			inf.RequiresProvenance = true
			break
		}
	}

	// Check for vulnerability scans
	for _, keyword := range []string{"vulnerabilit", "cve", "security scan", "vuln scan", "vulnerability scan"} {
		if strings.Contains(lowerReq, keyword) {
			inf.RequiresVulnScan = true
			break
		}
	}

	// Check for explicit predicate type URLs
	if strings.Contains(evidenceReq, "https://") {
		// Extract URL-like strings
		parts := strings.Fields(evidenceReq)
		for _, part := range parts {
			if strings.HasPrefix(part, "https://") {
				// This might be a custom attestation type
				if !isStandardAttestationType(part) {
					inf.CustomTypes = append(inf.CustomTypes, part)
				}
			}
		}
	}
}

// isStandardAttestationType checks if a URL is one of the standard attestation types.
func isStandardAttestationType(url string) bool {
	standardTypes := []string{
		"https://slsa.dev/provenance/v1",
		"https://in-toto.io/Statement/v0.1",
		"https://in-toto.io/Statement/v1",
	}

	for _, stdType := range standardTypes {
		if strings.Contains(url, stdType) {
			return true
		}
	}
	return false
}
