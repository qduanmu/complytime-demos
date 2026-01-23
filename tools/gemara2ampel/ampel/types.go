package ampel

import (
	"encoding/json"
)

// AmpelPolicy represents an Ampel verification policy that uses CEL
// (Common Expression Language) to verify attestations in the in-toto format.
//
// This structure matches the official Ampel policy format from
// github.com/carabiner-dev/policy/api/v1
type AmpelPolicy struct {
	// Id is the policy identifier
	Id string `json:"id"`

	// Meta contains policy metadata (description, assert mode, etc.)
	Meta *Meta `json:"meta,omitempty"`

	// Context contains contextual data definitions available to all tenets
	Context map[string]*ContextVal `json:"context,omitempty"`

	// Identities defines valid signer identities for attestations
	Identities []*Identity `json:"identities,omitempty"`

	// Predicates specifies which attestation types this policy evaluates
	Predicates *PredicateSpec `json:"predicates,omitempty"`

	// Tenets are the individual verification checks that make up this policy
	Tenets []*Tenet `json:"tenets,omitempty"`
}

// Meta contains metadata for an Ampel policy.
// Matches github.com/carabiner-dev/policy/api/v1.Meta
type Meta struct {
	// Runtime identifier (e.g., "cel@v14.0")
	Runtime string `json:"runtime,omitempty"`

	// Description provides context about the policy's purpose
	Description string `json:"description,omitempty"`

	// AssertMode controls if one tenet or all must pass ("AND" or "OR")
	// Default is "AND" (all tenets must pass)
	// Note: Official Ampel uses snake_case "assert_mode"
	AssertMode string `json:"assert_mode,omitempty"`

	// Controls lists compliance framework controls this policy addresses
	Controls []*Control `json:"controls,omitempty"`

	// Version is an integer marking the policy version
	Version int64 `json:"version,omitempty"`

	// Enforce controls if a FAILED policy returns FAILED or SOFTFAIL
	// Values: "ON"/"OFF", defaults to "ON"
	Enforce string `json:"enforce,omitempty"`
}

// Control represents a compliance framework control reference.
// Matches github.com/carabiner-dev/policy/api/v1.Control
type Control struct {
	// Id is the specific control identifier
	Id string `json:"id"`

	// Title is the human-readable control name
	Title string `json:"title,omitempty"`

	// Framework is the compliance framework name (e.g., "SLSA", "NIST")
	Framework string `json:"framework,omitempty"`

	// Class is the category within the framework (e.g., "BUILD")
	Class string `json:"class,omitempty"`

	// Item is an optional sub-item within the control
	Item string `json:"item,omitempty"`
}

// Tenet represents a single verification check with CEL code that evaluates
// attestations to verify compliance with a specific requirement.
// Matches github.com/carabiner-dev/policy/api/v1.Tenet
type Tenet struct {
	// Id uniquely identifies this tenet within the policy
	Id string `json:"id,omitempty"`

	// Title provides a human-readable name for the tenet
	Title string `json:"title,omitempty"`

	// Runtime identifier for this tenet (optional, inherits from policy if not set)
	Runtime string `json:"runtime,omitempty"`

	// Predicates specifies which attestation types this tenet evaluates
	Predicates *PredicateSpec `json:"predicates,omitempty"`

	// Code contains the CEL expression that performs the verification
	// The expression should evaluate to a boolean (true = pass, false = fail)
	Code string `json:"code"`

	// Outputs defines named outputs with CEL code to extract values
	Outputs map[string]*Output `json:"outputs,omitempty"`

	// Error defines error messaging for failed tenets
	Error *Error `json:"error,omitempty"`

	// Assessment contains tenet assessment results (optional, runtime field)
	Assessment *Assessment `json:"assessment,omitempty"`
}

// PredicateSpec defines which attestation predicate types a tenet or policy evaluates.
// Matches github.com/carabiner-dev/policy/api/v1.PredicateSpec
type PredicateSpec struct {
	// Types is a list of predicate type URIs (e.g., "https://slsa.dev/provenance/v1")
	Types []string `json:"types,omitempty"`

	// Limit is the maximum number of predicates to load (optional)
	Limit int32 `json:"limit,omitempty"`
}

// Output defines a CEL expression to extract an output value.
// Matches github.com/carabiner-dev/policy/api/v1.Output
type Output struct {
	// Code is the CEL expression to evaluate for this output
	Code string `json:"code"`

	// Value is the actual output value (populated at runtime)
	Value interface{} `json:"value,omitempty"`
}

// Error defines error messaging for failed tenets.
// Matches github.com/carabiner-dev/policy/api/v1.Error
type Error struct {
	// Message is the error message to display
	Message string `json:"message,omitempty"`

	// Guidance provides additional context or remediation steps
	Guidance string `json:"guidance,omitempty"`
}

// Assessment contains tenet assessment results.
// Matches github.com/carabiner-dev/policy/api/v1.Assessment
type Assessment struct {
	// Message is the assessment message
	Message string `json:"message,omitempty"`
}

// ContextVal defines a contextual data value with type and default.
// Matches github.com/carabiner-dev/policy/api/v1.ContextVal
type ContextVal struct {
	// Type of the context value ("string", "int", "bool", "float")
	Type string `json:"type,omitempty"`

	// Required indicates if this value must be provided
	Required *bool `json:"required,omitempty"`

	// Default is the default value if not provided
	Default interface{} `json:"default,omitempty"`

	// Value is the actual value (if set in the policy)
	Value interface{} `json:"value,omitempty"`

	// Description is a human-readable description
	Description *string `json:"description,omitempty"`
}

// Identity defines a valid signer identity for attestations.
// This is a simplified version of github.com/carabiner-dev/signer/api/v1.Identity
type Identity struct {
	// Type of identity matching (e.g., "exact", "regexp")
	Type string `json:"type,omitempty"`

	// Issuer is the identity provider (e.g., "https://accounts.google.com/")
	Issuer string `json:"issuer,omitempty"`

	// Identity is the specific identity value (e.g., email address)
	Identity string `json:"identity,omitempty"`

	// PublicKey contains a public key for verification (alternative to issuer/identity)
	PublicKey string `json:"publicKey,omitempty"`
}

// PolicySet contains multiple related Ampel policies that can be
// evaluated together. Supports both inline policies and policy references.
//
// This structure matches the official Ampel PolicySet format.
type PolicySet struct {
	// Id is an optional identifier for the policy set
	Id string `json:"id,omitempty"`

	// Meta contains policy set metadata
	Meta *PolicySetMetadata `json:"meta,omitempty"`

	// Policies contains the list of policies (inline or external references)
	Policies []*PolicyReference `json:"policies,omitempty"`
}

// PolicySetMetadata contains metadata for a PolicySet.
type PolicySetMetadata struct {
	// Description provides context about the policy set's purpose
	Description string `json:"description,omitempty"`

	// Version specifies the policy set version
	Version string `json:"version,omitempty"`

	// Additional custom metadata
	CustomMetadata map[string]interface{} `json:"customMetadata,omitempty"`
}

// PolicyReference represents either an inline policy or a reference to an external policy.
type PolicyReference struct {
	// Id uniquely identifies this policy within the set (optional for inline)
	Id string `json:"id,omitempty"`

	// Source specifies the location of an external policy (for remote policies)
	Source *PolicySource `json:"source,omitempty"`

	// Meta contains policy metadata (for inline policies)
	Meta *Meta `json:"meta,omitempty"`

	// Tenets are the verification checks (for inline policies)
	Tenets []*Tenet `json:"tenets,omitempty"`

	// Context contains contextual data (for inline policies)
	Context map[string]*ContextVal `json:"context,omitempty"`
}

// PolicySource specifies where to load a policy from.
type PolicySource struct {
	// Location contains the URI or path to the policy
	Location PolicyLocation `json:"location"`
}

// PolicyLocation specifies the exact location of a policy.
type PolicyLocation struct {
	// URI is the location of the policy (e.g., "git+https://github.com/...")
	URI string `json:"uri"`
}

// ToJSON serializes the Ampel policy to JSON format.
func (p *AmpelPolicy) ToJSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// ToJSONCompact serializes the Ampel policy to compact JSON format.
func (p *AmpelPolicy) ToJSONCompact() ([]byte, error) {
	return json.Marshal(p)
}

// ToJSON serializes the PolicySet to JSON format.
func (ps *PolicySet) ToJSON() ([]byte, error) {
	return json.MarshalIndent(ps, "", "  ")
}

// ToJSONCompact serializes the PolicySet to compact JSON format.
func (ps *PolicySet) ToJSONCompact() ([]byte, error) {
	return json.Marshal(ps)
}

// Validate checks if the PolicySet is well-formed.
func (ps *PolicySet) Validate() error {
	if len(ps.Policies) == 0 {
		return &ValidationError{Field: "policies", Message: "policy set must have at least one policy"}
	}
	for i, policyRef := range ps.Policies {
		if err := policyRef.Validate(); err != nil {
			return &ValidationError{Field: "policies", Index: i, Cause: err}
		}
	}
	return nil
}

// Validate checks if the PolicyReference is well-formed.
func (pr *PolicyReference) Validate() error {
	hasSource := pr.Source != nil
	hasTenets := len(pr.Tenets) > 0

	if !hasSource && !hasTenets {
		return &ValidationError{
			Field:   "policy reference",
			Message: "must have either source or inline tenets",
		}
	}

	// Validate source if present
	if hasSource {
		if pr.Source.Location.URI == "" {
			return &ValidationError{
				Field:   "source.location.uri",
				Message: "policy source URI is required",
			}
		}
	}

	// Validate inline policy if present
	if hasTenets {
		for i, tenet := range pr.Tenets {
			if err := tenet.Validate(); err != nil {
				return &ValidationError{Field: "tenets", Index: i, Cause: err}
			}
		}
	}

	return nil
}

// Validate checks if the Ampel policy is well-formed.
func (p *AmpelPolicy) Validate() error {
	if p.Id == "" {
		return &ValidationError{Field: "id", Message: "policy id is required"}
	}
	if len(p.Tenets) == 0 {
		return &ValidationError{Field: "tenets", Message: "policy must have at least one tenet"}
	}
	for i, tenet := range p.Tenets {
		if err := tenet.Validate(); err != nil {
			return &ValidationError{Field: "tenets", Index: i, Cause: err}
		}
	}
	return nil
}

// Validate checks if the Tenet is well-formed.
func (t *Tenet) Validate() error {
	if t.Code == "" {
		return &ValidationError{Field: "code", Message: "tenet code (CEL expression) is required"}
	}
	return nil
}

// ValidationError represents an error during policy validation.
type ValidationError struct {
	Field   string
	Index   int
	Message string
	Cause   error
}

func (e *ValidationError) Error() string {
	if e.Index >= 0 {
		if e.Cause != nil {
			return "validation error in " + e.Field + "[" + string(rune(e.Index)) + "]: " + e.Cause.Error()
		}
		return "validation error in " + e.Field + "[" + string(rune(e.Index)) + "]: " + e.Message
	}
	if e.Cause != nil {
		return "validation error in " + e.Field + ": " + e.Cause.Error()
	}
	return "validation error in " + e.Field + ": " + e.Message
}

func (e *ValidationError) Unwrap() error {
	return e.Cause
}
