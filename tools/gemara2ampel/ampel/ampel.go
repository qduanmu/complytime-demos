package ampel

import (
	"fmt"
	"path"
	"strconv"
	"strings"
	"unicode"

	"github.com/gemaraproj/go-gemara"
)

// FromPolicy converts a Gemara Layer-3 Policy to Ampel policy format.
//
// The function maps:
//   - Policy metadata to Ampel policy name/description/version
//   - Assessment plans to Ampel tenets with CEL expressions
//   - Evaluation methods (type: automated) to attestation verification logic
//   - Evidence requirements to expected attestation predicates
//   - Scope dimensions to CEL filtering expressions
//
// Options:
//   - WithCatalog: Include catalog data to enrich tenet descriptions
//   - WithCELTemplates: Custom CEL code templates for method types
//   - WithAttestationTypes: Specify expected attestation types
//   - WithScopeFilters: Generate scope-based CEL filters
//   - WithDefaultRule: Set overall policy rule (default: "all(tenets)")
func FromPolicy(policy *gemara.Policy, opts ...TransformOption) (AmpelPolicy, error) {
	options := &TransformOptions{}
	for _, opt := range opts {
		opt(options)
	}
	options.applyDefaults()

	ampelPolicy := AmpelPolicy{
		Id: policy.Metadata.Id,
		Meta: &Meta{
			Runtime:     "cel@v14.0",
			Description: policy.Metadata.Description,
			AssertMode:  ruleToAssertMode(options.DefaultRule),
		},
		Tenets: []*Tenet{},
	}

	// Transform metadata
	if err := buildMetadata(policy, &ampelPolicy); err != nil {
		return ampelPolicy, fmt.Errorf("error building metadata: %w", err)
	}

	// Convert assessment plans to tenets
	for _, plan := range policy.Adherence.AssessmentPlans {
		tenets, err := assessmentPlanToTenets(plan, policy, options)
		if err != nil {
			return ampelPolicy, fmt.Errorf("error converting assessment plan %s: %w", plan.Id, err)
		}
		ampelPolicy.Tenets = append(ampelPolicy.Tenets, tenets...)
	}

	// Validate the generated policy
	if err := ampelPolicy.Validate(); err != nil {
		return ampelPolicy, fmt.Errorf("generated policy validation failed: %w", err)
	}

	return ampelPolicy, nil
}

// ruleToAssertMode converts a policy rule string to AssertMode
// "all(tenets)" -> "AND", "any(tenets)" -> "OR"
func ruleToAssertMode(rule string) string {
	if strings.Contains(rule, "any") {
		return "OR"
	}
	return "AND"
}

// buildMetadata extracts metadata from Gemara policy and populates Ampel policy metadata.
func buildMetadata(policy *gemara.Policy, ampelPolicy *AmpelPolicy) error {
	// Parse version string to int64
	version := int64(0)
	if policy.Metadata.Version != "" {
		// Try to parse version (e.g., "1.0.0" -> 1)
		parts := strings.Split(policy.Metadata.Version, ".")
		if len(parts) > 0 {
			if v, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
				version = v
			}
		}
	}
	ampelPolicy.Meta.Version = version

	// Note: The official Ampel policy format doesn't include author, contacts, or scope
	// These could be added to a custom metadata extension if needed

	return nil
}

// assessmentPlanToTenets converts a single assessment plan to one or more Ampel tenets.
func assessmentPlanToTenets(
	plan gemara.AssessmentPlan,
	policy *gemara.Policy,
	options *TransformOptions,
) ([]*Tenet, error) {
	var tenets []*Tenet

	// Get evidence requirements
	evidenceReq := plan.EvidenceRequirements

	// Process each evaluation method
	methodIndex := 0
	for _, method := range plan.EvaluationMethods {
		// Only process automated methods
		if !isAutomatedMethod(method.Type) {
			continue
		}

		// Build tenet parameters from plan parameters
		tenetParams := make(map[string]interface{})
		celParams := make(map[string]interface{})

		for _, param := range plan.Parameters {
			if len(param.AcceptedValues) > 0 {
				// Store parameter value(s) in tenetParams
				if len(param.AcceptedValues) == 1 {
					// Single value: store as string
					tenetParams[param.Id] = param.AcceptedValues[0]
				} else {
					// Multiple values: store as array
					tenetParams[param.Id] = param.AcceptedValues
				}

				// Convert parameter ID to PascalCase for CEL templates
				// Example: "builder-id" -> "BuilderId"
				pascalCaseId := kebabToPascal(param.Id)
				celParams[pascalCaseId] = param.AcceptedValues[0]

				// For multiple accepted values, format as list for CEL
				if len(param.AcceptedValues) > 1 {
					var quotedValues []string
					for _, val := range param.AcceptedValues {
						quotedValues = append(quotedValues, fmt.Sprintf(`"%s"`, val))
					}
					celParams[pascalCaseId+"s"] = strings.Join(quotedValues, ", ")
				}
			}
		}

		// Generate CEL expression
		celCode, attestationTypes, err := GenerateCELFromMethod(method, evidenceReq, celParams, options.CELTemplates)
		if err != nil {
			return nil, fmt.Errorf("error generating CEL for method %d: %w", methodIndex, err)
		}

		// Apply scope filters if enabled
		if options.IncludeScopeFilters {
			scopeFilter := ScopeFilterToCEL(policy.Scope.In)
			if scopeFilter != "" {
				celCode = fmt.Sprintf("(%s) && (%s)", scopeFilter, celCode)
			}
		}

		// Build tenet title - use method description or evidence requirement
		title := getTenetName(method, evidenceReq)

		// Create tenet with official Ampel format
		tenet := &Tenet{
			Id:      fmt.Sprintf("%s-%s-%d", plan.RequirementId, plan.Id, methodIndex),
			Title:   title,
			Runtime: "cel@v14.0",
			Code:    celCode,
		}

		// Add PredicateSpec with attestation types
		if len(attestationTypes) > 0 {
			tenet.Predicates = &PredicateSpec{
				Types: attestationTypes,
			}
		}

		// Store parameters in Outputs using the official Output format
		if len(tenetParams) > 0 {
			tenet.Outputs = make(map[string]*Output)
			for key := range tenetParams {
				// Create CEL code to access the parameter from context
				celCode := fmt.Sprintf("context.%s", key)
				tenet.Outputs[key] = &Output{
					Code: celCode,
				}
			}
		}

		tenets = append(tenets, tenet)
		methodIndex++
	}

	return tenets, nil
}

// getTenetName determines an appropriate name for a tenet based on the method and evidence.
func getTenetName(method gemara.AcceptedMethod, evidenceReq string) string {
	if method.Description != "" {
		return method.Description
	}

	// Generate name from evidence requirement
	if evidenceReq != "" {
		// Capitalize first letter and limit length
		name := strings.TrimSpace(evidenceReq)
		if len(name) > 80 {
			name = name[:77] + "..."
		}
		return name
	}

	// Fallback to method type
	return fmt.Sprintf("%s verification", method.Type)
}

// isAutomatedMethod checks if an evaluation method type can be automated.
func isAutomatedMethod(methodType string) bool {
	automatedTypes := map[string]bool{
		"automated":       true,
		"gate":            true,
		"behavioral":      true,
		"autoremediation": true,
	}
	return automatedTypes[methodType]
}

// FromPolicies converts multiple Gemara Layer-3 Policies to an Ampel PolicySet.
//
// This function creates a PolicySet with inline policies from the provided Gemara policies.
// Each policy is transformed using FromPolicy and embedded directly in the PolicySet.
//
// Options:
//   - WithPolicySetMetadata: Set name, description, and version for the PolicySet
//   - WithCatalog: Include catalog data to enrich tenet descriptions
//   - WithCELTemplates: Custom CEL code templates for method types
//   - WithAttestationTypes: Specify expected attestation types
//   - WithScopeFilters: Generate scope-based CEL filters
//   - WithDefaultRule: Set overall policy rule (default: "all(tenets)")
func FromPolicies(policies []*gemara.Policy, opts ...PolicySetOption) (PolicySet, error) {
	if len(policies) == 0 {
		return PolicySet{}, fmt.Errorf("at least one policy is required")
	}

	// Apply policy set options
	psOptions := &PolicySetOptions{}
	for _, opt := range opts {
		opt(psOptions)
	}

	policySet := PolicySet{
		Id: psOptions.Name,
		Meta: &PolicySetMetadata{
			Description:    psOptions.Description,
			Version:        psOptions.Version,
			CustomMetadata: psOptions.Metadata,
		},
		Policies: []*PolicyReference{},
	}

	// Convert each Gemara policy to Ampel policy
	for _, gemaraPolicy := range policies {
		ampelPolicy, err := FromPolicy(gemaraPolicy, psOptions.TransformOptions...)
		if err != nil {
			return policySet, fmt.Errorf("error converting policy %s: %w", gemaraPolicy.Metadata.Id, err)
		}

		// Create inline policy reference by copying fields from AmpelPolicy
		policyRef := &PolicyReference{
			Id:      ampelPolicy.Id,
			Meta:    ampelPolicy.Meta,
			Tenets:  ampelPolicy.Tenets,
			Context: ampelPolicy.Context,
		}

		// Override metadata if provided in options
		if psOptions.Meta != nil {
			if meta, ok := psOptions.Meta[gemaraPolicy.Metadata.Id]; ok {
				policyRef.Meta = meta
			}
		}

		policySet.Policies = append(policySet.Policies, policyRef)
	}

	// Validate the generated policy set
	if err := policySet.Validate(); err != nil {
		return policySet, fmt.Errorf("generated policy set validation failed: %w", err)
	}

	return policySet, nil
}

// FromPolicyWithImports converts a Gemara Layer-3 Policy and its imports to an Ampel PolicySet.
//
// This function creates a PolicySet where:
//   - The main policy is converted to an inline Ampel policy
//   - Imported policies are added as external references
//
// Options:
//   - WithPolicySetMetadata: Set name, description, and version for the PolicySet
//   - WithCatalog: Include catalog data to enrich tenet descriptions
//   - WithCELTemplates: Custom CEL code templates for method types
func FromPolicyWithImports(policy *gemara.Policy, opts ...PolicySetOption) (PolicySet, error) {
	// Apply policy set options
	psOptions := &PolicySetOptions{}
	for _, opt := range opts {
		opt(psOptions)
	}

	// Set PolicySet metadata (default to main policy metadata if not provided)
	policySetId := psOptions.Name
	if policySetId == "" {
		policySetId = policy.Metadata.Id + "-set"
	}

	policySetDesc := psOptions.Description
	if policySetDesc == "" {
		policySetDesc = policy.Metadata.Description
	}

	policySetVersion := psOptions.Version
	if policySetVersion == "" {
		policySetVersion = policy.Metadata.Version
	}

	policySet := PolicySet{
		Id: policySetId,
		Meta: &PolicySetMetadata{
			Description:    policySetDesc,
			Version:        policySetVersion,
			CustomMetadata: psOptions.Metadata,
		},
		Policies: []*PolicyReference{},
	}

	// Convert the main policy
	ampelPolicy, err := FromPolicy(policy, psOptions.TransformOptions...)
	if err != nil {
		return policySet, fmt.Errorf("error converting main policy: %w", err)
	}

	// Create inline policy reference
	mainPolicyRef := &PolicyReference{
		Id:      ampelPolicy.Id,
		Meta:    ampelPolicy.Meta,
		Tenets:  ampelPolicy.Tenets,
		Context: ampelPolicy.Context,
	}

	// Override metadata for main policy if provided
	if psOptions.Meta != nil {
		if meta, ok := psOptions.Meta[policy.Metadata.Id]; ok {
			mainPolicyRef.Meta = meta
		}
	}

	policySet.Policies = append(policySet.Policies, mainPolicyRef)

	// Add imported policies as external references
	for _, importedPolicyRef := range policy.Imports.Policies {
		policyRef := &PolicyReference{
			Id: extractPolicyIdFromReference(importedPolicyRef),
			Source: &PolicySource{
				Location: PolicyLocation{
					URI: importedPolicyRef,
				},
			},
		}

		// Add metadata for imported policy if provided
		if psOptions.Meta != nil {
			if meta, ok := psOptions.Meta[policyRef.Id]; ok {
				policyRef.Meta = meta
			}
		}

		policySet.Policies = append(policySet.Policies, policyRef)
	}

	// Validate the generated policy set
	if err := policySet.Validate(); err != nil {
		return policySet, fmt.Errorf("generated policy set validation failed: %w", err)
	}

	return policySet, nil
}

// extractPolicyIdFromReference extracts a policy ID from a reference string.
// For URIs like "git+https://github.com/org/repo#path/to/policy.json",
// it extracts "policy" from the filename.
func extractPolicyIdFromReference(reference string) string {
	// Try to extract from fragment first (after #)
	parts := strings.Split(reference, "#")
	if len(parts) > 1 {
		// Get the last part (the path after #)
		policyPath := parts[len(parts)-1]
		// Extract filename without extension
		base := path.Base(policyPath)
		ext := path.Ext(base)
		if ext != "" {
			return strings.TrimSuffix(base, ext)
		}
		return base
	}

	// Fallback: use the whole reference as ID
	return reference
}

// kebabToPascal converts kebab-case to PascalCase for template parameters.
// Examples: "builder-id" -> "BuilderId", "scanner" -> "Scanner"
func kebabToPascal(s string) string {
	parts := strings.Split(s, "-")
	var result strings.Builder
	for _, part := range parts {
		if len(part) > 0 {
			// Capitalize first letter of each part
			runes := []rune(part)
			runes[0] = unicode.ToUpper(runes[0])
			result.WriteString(string(runes))
		}
	}
	return result.String()
}
