package ampel

import (
	"testing"

	"github.com/gemaraproj/go-gemara"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFromPolicy_Basic tests basic policy transformation without options.
func TestFromPolicy_Basic(t *testing.T) {
	policy := createTestPolicy()

	ampelPolicy, err := FromPolicy(policy)
	require.NoError(t, err)

	// Verify basic fields - Id comes from policy.Metadata.Id now
	assert.Equal(t, "policy-001", ampelPolicy.Id)
	// Version is parsed as int64 from "1.0.0" -> 1
	assert.Equal(t, int64(1), ampelPolicy.Meta.Version)
	assert.Equal(t, "Test policy description", ampelPolicy.Meta.Description)
	// AssertMode is "AND" (converted from "all(tenets)")
	assert.Equal(t, "AND", ampelPolicy.Meta.AssertMode)
	// Runtime is set to default cel@v14.0
	assert.Equal(t, "cel@v14.0", ampelPolicy.Meta.Runtime)

	// Verify tenets were created
	assert.Greater(t, len(ampelPolicy.Tenets), 0, "Policy should have at least one tenet")
}

// TestFromPolicy_WithCatalog tests policy transformation with catalog enrichment.
func TestFromPolicy_WithCatalog(t *testing.T) {
	policy := createTestPolicy()
	catalog := createTestCatalog()

	ampelPolicy, err := FromPolicy(policy, WithCatalog(catalog))
	require.NoError(t, err)

	// Verify tenets were generated from catalog
	// Note: Catalog enrichment functionality exists but tenet description field was removed
	assert.NotEmpty(t, ampelPolicy.Tenets, "Expected tenets to be generated from catalog")
}

// TestFromPolicy_WithScopeFilters tests scope-based CEL filter generation.
func TestFromPolicy_WithScopeFilters(t *testing.T) {
	policy := createTestPolicy()

	ampelPolicy, err := FromPolicy(policy, WithScopeFilters(true))
	require.NoError(t, err)

	// Verify tenets include scope filters in CEL code
	if len(ampelPolicy.Tenets) > 0 {
		tenet := ampelPolicy.Tenets[0]
		// Scope filters should be present in CEL code
		assert.Contains(t, tenet.Code, "subject", "CEL code should include scope filters")
	}
}

// TestAssessmentPlanToTenets tests conversion of assessment plans to tenets.
func TestAssessmentPlanToTenets(t *testing.T) {
	policy := createTestPolicy()
	plan := createTestAssessmentPlan()

	tenets, err := assessmentPlanToTenets(plan, policy, &TransformOptions{
		CELTemplates: DefaultCELTemplates,
		DefaultRule:  "all(tenets)",
	})
	require.NoError(t, err)

	// Should create one tenet for the automated method
	assert.Len(t, tenets, 1)

	tenet := tenets[0]
	assert.Equal(t, "REQ-01-plan-01-0", tenet.Id)
	assert.Equal(t, "Verify SLSA provenance", tenet.Title)
	assert.NotEmpty(t, tenet.Code)
	assert.Contains(t, tenet.Code, "attestation.predicateType")
}

// TestGenerateCELFromMethod tests CEL expression generation from evaluation methods.
func TestGenerateCELFromMethod(t *testing.T) {
	tests := []struct {
		name            string
		method          gemara.AcceptedMethod
		evidenceReq     string
		expectedInCode  string
		expectedAttType string
	}{
		{
			name: "SLSA provenance",
			method: gemara.AcceptedMethod{
				Type: "automated",
			},
			evidenceReq:     "SLSA provenance with trusted builder",
			expectedInCode:  "slsa.dev/provenance/v1",
			expectedAttType: "https://slsa.dev/provenance/v1",
		},
		{
			name: "Vulnerability scan",
			method: gemara.AcceptedMethod{
				Type: "automated",
			},
			evidenceReq:     "Vulnerability scan with no critical findings",
			expectedInCode:  "in-toto.io/Statement",
			expectedAttType: "https://in-toto.io/Statement/v0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			celCode, attTypes, err := GenerateCELFromMethod(
				tt.method,
				tt.evidenceReq,
				make(map[string]interface{}),
				DefaultCELTemplates,
			)
			require.NoError(t, err)

			assert.Contains(t, celCode, tt.expectedInCode)
			if len(attTypes) > 0 {
				assert.Contains(t, attTypes[0], tt.expectedAttType)
			}
		})
	}
}

// TestInferAttestationType tests attestation type inference from evidence requirements.
func TestInferAttestationType(t *testing.T) {
	tests := []struct {
		evidenceReq string
		expected    string
	}{
		{"SLSA provenance attestation", "https://slsa.dev/provenance/v1"},
		{"Build provenance with builder details", "https://slsa.dev/provenance/v1"},
		{"Vulnerability scan results", "https://in-toto.io/Statement/v0.1"},
		{"CVE scanning with no critical issues", "https://in-toto.io/Statement/v0.1"},
		{"Generic attestation", "https://in-toto.io/Statement/v0.1"},
		{"Unknown requirement", ""},
	}

	for _, tt := range tests {
		t.Run(tt.evidenceReq, func(t *testing.T) {
			result := InferAttestationType(tt.evidenceReq)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestInferAttestationTypes tests policy-level attestation type inference.
func TestInferAttestationTypes(t *testing.T) {
	policy := createTestPolicy()

	inference := InferAttestationTypes(policy)

	// Should detect SLSA provenance from the test policy
	assert.True(t, inference.RequiresProvenance)

	// Get all types
	allTypes := inference.AllTypes()
	assert.Contains(t, allTypes, "https://slsa.dev/provenance/v1")
}

// TestScopeFilterToCEL tests conversion of scope dimensions to CEL filters.
func TestScopeFilterToCEL(t *testing.T) {
	dimensions := gemara.Dimensions{
		Technologies: []string{"Cloud Computing", "Web Applications"},
		Geopolitical: []string{"United States", "European Union"},
		Sensitivity:  []string{"Confidential", "Secret"},
	}

	celFilter := ScopeFilterToCEL(dimensions)

	// Verify all dimensions are included
	assert.Contains(t, celFilter, "subject.type")
	assert.Contains(t, celFilter, "cloud-computing")
	assert.Contains(t, celFilter, "web-applications")
	assert.Contains(t, celFilter, "subject.annotations.region")
	assert.Contains(t, celFilter, "us")
	assert.Contains(t, celFilter, "eu")
	assert.Contains(t, celFilter, "subject.annotations.classification")
	assert.Contains(t, celFilter, "confidential")
	assert.Contains(t, celFilter, "secret")
}

// TestPolicyValidation tests the validation of generated policies.
func TestPolicyValidation(t *testing.T) {
	t.Run("valid policy", func(t *testing.T) {
		policy := AmpelPolicy{
			Id: "test-policy",
			Tenets: []*Tenet{
				{
					Id:    "test-1",
					Title: "Test Tenet",
					Code:  "true",
				},
			},
		}
		err := policy.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing name", func(t *testing.T) {
		policy := AmpelPolicy{
			Tenets: []*Tenet{
				{
					Id:    "test-1",
					Title: "Test Tenet",
					Code:  "true",
				},
			},
		}
		err := policy.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "id")
	})

	t.Run("no tenets", func(t *testing.T) {
		policy := AmpelPolicy{
			Id:     "test-policy",
			Tenets: []*Tenet{},
		}
		err := policy.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "tenet")
	})
}

// TestTenetValidation tests the validation of tenets.
func TestTenetValidation(t *testing.T) {
	t.Run("valid tenet", func(t *testing.T) {
		tenet := Tenet{
			Id:    "test-1",
			Title: "Test Tenet",
			Code:  "attestation.predicateType == \"https://slsa.dev/provenance/v1\"",
		}
		err := tenet.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing ID", func(t *testing.T) {
		tenet := Tenet{
			Title: "Test Tenet",
			Code:  "true",
		}
		err := tenet.Validate()
		// ID is optional in official Ampel format
		assert.NoError(t, err)
	})

	t.Run("missing code", func(t *testing.T) {
		tenet := Tenet{
			Id:    "test-1",
			Title: "Test Tenet",
		}
		err := tenet.Validate()
		assert.Error(t, err)
	})
}

// TestToJSON tests JSON serialization of policies.
func TestToJSON(t *testing.T) {
	policy := AmpelPolicy{
		Id: "test-policy",
		Meta: &Meta{
			Version:    1,
			AssertMode: "AND",
		},
		Tenets: []*Tenet{
			{
				Id:    "test-1",
				Title: "Test Tenet",
				Code:  "true",
			},
		},
	}

	json, err := policy.ToJSON()
	require.NoError(t, err)

	// Verify JSON structure - new format uses "id" instead of "name"
	jsonStr := string(json)
	assert.Contains(t, jsonStr, "\"id\": \"test-policy\"")
	assert.Contains(t, jsonStr, "\"version\": 1")
	assert.Contains(t, jsonStr, "\"tenets\"")
	// Official Ampel format uses snake_case "assert_mode"
	assert.Contains(t, jsonStr, "\"assert_mode\": \"AND\"")
}

// Helper functions to create test data

func createTestPolicy() *gemara.Policy {
	return &gemara.Policy{
		Title: "Test Security Policy",
		Metadata: gemara.Metadata{
			Id:          "policy-001",
			Version:     "1.0.0",
			Description: "Test policy description",
			Author: gemara.Actor{
				Name: "Test Author",
				Id:   "author-001",
			},
		},
		Contacts: gemara.Contacts{
			Responsible: []gemara.Contact{
				{Name: "IT Director"},
			},
			Accountable: []gemara.Contact{
				{Name: "CISO"},
			},
		},
		Scope: gemara.Scope{
			In: gemara.Dimensions{
				Technologies: []string{"Cloud Computing"},
				Geopolitical: []string{"United States"},
			},
		},
		Imports: gemara.Imports{},
		Adherence: gemara.Adherence{
			AssessmentPlans: []gemara.AssessmentPlan{
				{
					Id:                   "plan-01",
					RequirementId:        "REQ-01",
					Frequency:            "continuous",
					EvidenceRequirements: "SLSA provenance with trusted builder",
					EvaluationMethods: []gemara.AcceptedMethod{
						{
							Type:        "automated",
							Description: "Verify SLSA provenance",
						},
					},
				},
			},
		},
	}
}

func createTestAssessmentPlan() gemara.AssessmentPlan {
	return gemara.AssessmentPlan{
		Id:                   "plan-01",
		RequirementId:        "REQ-01",
		Frequency:            "continuous",
		EvidenceRequirements: "SLSA provenance with trusted builder",
		EvaluationMethods: []gemara.AcceptedMethod{
			{
				Type:        "automated",
				Description: "Verify SLSA provenance",
			},
		},
	}
}

func createTestCatalog() *gemara.Catalog {
	return &gemara.Catalog{
		Title: "Test Catalog",
		Metadata: gemara.Metadata{
			Id:          "catalog-001",
			Version:     "1.0",
			Description: "Test catalog",
		},
		Families: []gemara.Family{
			{
				Id:          "CF-01",
				Title:       "Test Control Family",
				Description: "Test control family description",
			},
		},
		Controls: []gemara.Control{
			{
				Id:        "CTRL-01",
				Title:     "Test Control",
				Objective: "Test control objective",
				Family:    "CF-01",
				AssessmentRequirements: []gemara.AssessmentRequirement{
					{
						Id:   "REQ-01",
						Text: "Verify build provenance is present and valid",
					},
				},
			},
		},
	}
}

// TestFromPolicies tests converting multiple Gemara policies to PolicySet.
func TestFromPolicies(t *testing.T) {
	policy1 := createTestPolicy()
	policy1.Metadata.Id = "policy-001"
	policy1.Title = "Policy One"

	policy2 := &gemara.Policy{
		Title: "Policy Two",
		Metadata: gemara.Metadata{
			Id:          "policy-002",
			Version:     "1.0.0",
			Description: "Second test policy",
			Author: gemara.Actor{
				Name: "Test Author 2",
			},
		},
		Contacts: gemara.Contacts{},
		Scope:    gemara.Scope{},
		Imports:  gemara.Imports{},
		Adherence: gemara.Adherence{
			AssessmentPlans: []gemara.AssessmentPlan{
				{
					Id:                   "plan-02",
					RequirementId:        "REQ-02",
					Frequency:            "daily",
					EvidenceRequirements: "Vulnerability scan with no critical findings",
					EvaluationMethods: []gemara.AcceptedMethod{
						{
							Type:        "automated",
							Description: "Verify vulnerability scan results",
						},
					},
				},
			},
		},
	}

	policies := []*gemara.Policy{policy1, policy2}

	policySet, err := FromPolicies(policies,
		WithPolicySetMetadata("Test Policy Set", "Collection of test policies", "1.0.0"),
	)
	require.NoError(t, err)

	// Verify PolicySet metadata
	assert.Equal(t, "Test Policy Set", policySet.Id)
	assert.Equal(t, "Collection of test policies", policySet.Meta.Description)
	assert.Equal(t, "1.0.0", policySet.Meta.Version)

	// Verify policies were converted
	assert.Len(t, policySet.Policies, 2)

	// Verify first policy (inline policy)
	assert.Equal(t, "policy-001", policySet.Policies[0].Id)
	assert.NotNil(t, policySet.Policies[0].Tenets)
	assert.Nil(t, policySet.Policies[0].Source)

	// Verify second policy (inline policy)
	assert.Equal(t, "policy-002", policySet.Policies[1].Id)
	assert.NotNil(t, policySet.Policies[1].Tenets)
	assert.Nil(t, policySet.Policies[1].Source)
}

// TestFromPolicyWithImports tests converting a policy with imports to PolicySet.
func TestFromPolicyWithImports(t *testing.T) {
	policy := createTestPolicy()
	policy.Metadata.Id = "main-policy"
	policy.Title = "Main Policy"
	policy.Imports.Policies = []string{
		"git+https://github.com/carabiner-dev/policies#slsa/slsa-builder-id.json",
		"git+https://github.com/carabiner-dev/policies#vuln/vuln-scan.json",
	}

	policySet, err := FromPolicyWithImports(policy)
	require.NoError(t, err)

	// Verify PolicySet metadata defaults to main policy
	assert.Contains(t, policySet.Id, "main-policy")
	assert.Equal(t, policy.Metadata.Description, policySet.Meta.Description)
	assert.Equal(t, policy.Metadata.Version, policySet.Meta.Version)

	// Verify policies: 1 inline + 2 references
	assert.Len(t, policySet.Policies, 3)

	// Verify main policy is inline
	assert.Equal(t, "main-policy", policySet.Policies[0].Id)
	assert.NotNil(t, policySet.Policies[0].Tenets)
	assert.Nil(t, policySet.Policies[0].Source)

	// Verify first import is a reference
	assert.Equal(t, "slsa-builder-id", policySet.Policies[1].Id)
	assert.Nil(t, policySet.Policies[1].Tenets)
	assert.NotNil(t, policySet.Policies[1].Source)
	assert.Equal(t, "git+https://github.com/carabiner-dev/policies#slsa/slsa-builder-id.json",
		policySet.Policies[1].Source.Location.URI)

	// Verify second import is a reference
	assert.Equal(t, "vuln-scan", policySet.Policies[2].Id)
	assert.Nil(t, policySet.Policies[2].Tenets)
	assert.NotNil(t, policySet.Policies[2].Source)
	assert.Equal(t, "git+https://github.com/carabiner-dev/policies#vuln/vuln-scan.json",
		policySet.Policies[2].Source.Location.URI)
}

// TestFromPoliciesWithMeta tests adding metadata to policies in a PolicySet.
func TestFromPoliciesWithMeta(t *testing.T) {
	policy := createTestPolicy()
	policy.Metadata.Id = "slsa-policy"

	meta := &Meta{
		Controls: []*Control{
			{
				Framework: "SLSA",
				Class:     "BUILD",
				Id:        "LEVEL_3",
			},
		},
		Enforce: "ON",
	}

	policySet, err := FromPolicies([]*gemara.Policy{policy},
		WithMeta("slsa-policy", meta),
	)
	require.NoError(t, err)

	// Verify metadata was attached
	assert.Len(t, policySet.Policies, 1)
	assert.NotNil(t, policySet.Policies[0].Meta)
	assert.Equal(t, "ON", policySet.Policies[0].Meta.Enforce)
	assert.Len(t, policySet.Policies[0].Meta.Controls, 1)
	assert.Equal(t, "SLSA", policySet.Policies[0].Meta.Controls[0].Framework)
	assert.Equal(t, "BUILD", policySet.Policies[0].Meta.Controls[0].Class)
	assert.Equal(t, "LEVEL_3", policySet.Policies[0].Meta.Controls[0].Id)
}

// TestPolicySetValidation tests PolicySet validation.
func TestPolicySetValidation(t *testing.T) {
	t.Run("valid inline policy", func(t *testing.T) {
		policySet := PolicySet{
			Policies: []*PolicyReference{
				{
					Id: "policy-001",
					Tenets: []*Tenet{
						{
							Id:    "test-1",
							Title: "Test Tenet",
							Code:  "true",
						},
					},
				},
			},
		}
		err := policySet.Validate()
		assert.NoError(t, err)
	})

	t.Run("valid policy reference", func(t *testing.T) {
		policySet := PolicySet{
			Policies: []*PolicyReference{
				{
					Id: "external-policy",
					Source: &PolicySource{
						Location: PolicyLocation{
							URI: "git+https://example.com/policy.json",
						},
					},
				},
			},
		}
		err := policySet.Validate()
		assert.NoError(t, err)
	})

	t.Run("missing policy ID", func(t *testing.T) {
		policySet := PolicySet{
			Policies: []*PolicyReference{
				{
					Tenets: []*Tenet{
						{
							Id:    "test-1",
							Title: "Test Tenet",
							Code:  "true",
						},
					},
				},
			},
		}
		err := policySet.Validate()
		// Validation should pass - Id is optional for inline policies in PolicySet
		assert.NoError(t, err)
	})

	t.Run("no policies", func(t *testing.T) {
		policySet := PolicySet{
			Policies: []*PolicyReference{},
		}
		err := policySet.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "at least one policy")
	})

	t.Run("neither source nor policy", func(t *testing.T) {
		policySet := PolicySet{
			Policies: []*PolicyReference{
				{
					Id: "policy-001",
					// No source and no tenets
				},
			},
		}
		err := policySet.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "source or inline tenets")
	})

	t.Run("missing source URI", func(t *testing.T) {
		policySet := PolicySet{
			Policies: []*PolicyReference{
				{
					Id:     "policy-001",
					Source: &PolicySource{},
				},
			},
		}
		err := policySet.Validate()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "URI")
	})
}

// TestPolicySetToJSON tests PolicySet JSON serialization.
func TestPolicySetToJSON(t *testing.T) {
	policySet := PolicySet{
		Id: "test-policyset",
		Meta: &PolicySetMetadata{
			Description: "Test description",
			Version:     "1.0.0",
		},
		Policies: []*PolicyReference{
			{
				Id: "policy-001",
				Tenets: []*Tenet{
					{
						Id:    "test-1",
						Title: "Test Tenet",
						Code:  "true",
					},
				},
			},
		},
	}

	json, err := policySet.ToJSON()
	require.NoError(t, err)

	jsonStr := string(json)
	// New format uses "id" instead of "name"
	assert.Contains(t, jsonStr, "\"id\": \"test-policyset\"")
	assert.Contains(t, jsonStr, "\"description\": \"Test description\"")
	assert.Contains(t, jsonStr, "\"version\": \"1.0.0\"")
	assert.Contains(t, jsonStr, "\"policies\"")
	assert.Contains(t, jsonStr, "\"id\": \"policy-001\"")
}

// TestExtractPolicyIdFromReference tests policy ID extraction from URIs.
func TestExtractPolicyIdFromReference(t *testing.T) {
	tests := []struct {
		reference string
		expected  string
	}{
		{
			reference: "git+https://github.com/org/repo#path/to/policy.json",
			expected:  "policy",
		},
		{
			reference: "git+https://github.com/carabiner-dev/policies#slsa/slsa-builder-id.json",
			expected:  "slsa-builder-id",
		},
		{
			reference: "https://example.com/policy.yaml",
			expected:  "https://example.com/policy.yaml",
		},
		{
			reference: "simple-reference",
			expected:  "simple-reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.reference, func(t *testing.T) {
			result := extractPolicyIdFromReference(tt.reference)
			assert.Equal(t, tt.expected, result)
		})
	}
}
