# Gemara to Ampel Converter

This directory contains tools for converting Gemara Layer 3 policy files to Ampel verification policy format.

## Overview

The `gemara2ampel` tools convert Gemara Layer 3 policies (organizational governance policies) into Ampel verification policies. Gemara policies define *what* controls are required, while Ampel policies define *how* to verify compliance through attestation checking.

### About Ampel

[Ampel](https://github.com/carabiner-dev/ampel) is "The Amazing Multipurpose Policy Engine (and L)" - a lightweight supply chain policy engine designed to verify unforgeable metadata captured in signed attestations throughout the software development lifecycle.

**Output Format:** This tool generates policies that conform to the official [Ampel Policy API v1](https://github.com/carabiner-dev/policy/tree/main/api/v1) format, using CEL (Common Expression Language) for verification logic.

## Go Implementation

A compiled Go implementation with full support for Gemara Layer 3 schema.

### Build
```bash
make build
```

Or manually:
```bash
go build -o bin/ampel_export ./cmd/ampel_export
```

### Usage
```bash
# Generate policy (output: policy-name.json based on input filename)
bin/ampel_export <policy.yaml>

# Output to specific file
bin/ampel_export <policy.yaml> -o <output.json>

# With catalog enrichment
bin/ampel_export <policy.yaml> -c <catalog.yaml> -o <output.json>

# With scope filters
bin/ampel_export <policy.yaml> --scope-filters -o <output.json>

# Generate PolicySet with imports
bin/ampel_export <policy.yaml> --policyset -o <output.json>

# Workspace mode (preserves manual CEL edits on regeneration)
bin/ampel_export <policy.yaml> -w ./policies

# Force regeneration (discard manual changes)
bin/ampel_export <policy.yaml> -w ./policies --force-overwrite

# Get help
bin/ampel_export --help

# Show version
bin/ampel_export --version
```

### Command-Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-o`, `--output` | Output file path | Input filename with .json extension |
| `-w`, `--workspace` | Workspace directory for policy management | - |
| `--force-overwrite` | Force regeneration, discard manual changes | false |
| `-c`, `--catalog` | Catalog file for enriching policy details | - |
| `--scope-filters` | Include scope-based CEL filters in tenets | false |
| `--policyset` | Generate a PolicySet with imports as external references | false |
| `--policyset-name` | Name for the PolicySet (only used with --policyset) | - |
| `--policyset-description` | Description for the PolicySet | - |
| `--policyset-version` | Version for the PolicySet | - |
| `-h`, `--help` | Show help message | - |
| `-v`, `--version` | Show version information | - |

### Examples

```bash
# Build the tool
make build

# Basic conversion
bin/ampel_export test_data/gemara-policy-with-params.yaml -output my-policy.json

# Generate PolicySet with scope filters
bin/ampel_export test_data/gemara-policy-with-params.yaml -policyset -scope-filters -output policyset.json
```

### Features
- **Full Gemara Layer 3 schema support** via `github.com/gemaraproj/go-gemara`
- **Official Ampel API compliance** - Uses official Ampel Policy API types from `github.com/carabiner-dev/policy/api/v1`
  - Direct type aliases to official v1 types (Policy, PolicySet, Tenet, etc.)
  - Uses snake_case field names (e.g., `assert_mode`)
  - CEL runtime version `cel@v14.0`
  - PredicateSpec for attestation type filtering
- **Workspace mode** - Preserves manual CEL edits on policy regeneration
- **Smart parameter handling** - Parameters mapped to Policy.Context with runtime value support
- **Catalog enrichment** - Enriches tenet titles from catalog requirement text and adds control metadata
- **Scope-based CEL filter generation**
- **PolicySet generation** with import handling (inline and external references)
- **Template-based CEL code generation**
- **Automatic attestation type inference** from evidence requirements
- **Cobra CLI** with short flags, help, and version support

### Dependencies
The Go version uses the following dependencies:
- `github.com/gemaraproj/go-gemara` (latest from main branch) - Gemara schema definitions
- `github.com/spf13/cobra v1.10.2` - CLI framework
- `github.com/goccy/go-yaml v1.19.1` - YAML parsing

## Transformation Overview

### What Gets Mapped

The transformation focuses on converting **verification-relevant** policy elements:

**Included:**
- Policy ID and description
- Assessment plans → Tenets with CEL expressions
- Evaluation methods (automated, gate, behavioral, autoremediation)
- Evidence requirements → Attestation type specifications
- Parameters → Policy.Context with runtime values and defaults
- Scope dimensions → CEL filters (when `--scope-filters` enabled)

**Not Included:**
- Author and contact information (RACI model)
- Implementation timelines and rollout schedules
- Risk assessments and mitigation strategies
- Enforcement methods and remediation workflows
- Organizational metadata

These organizational fields contain valuable governance context but are not part of the technical verification policy structure defined by the official Ampel format.

### Field Mappings

For detailed field mapping documentation, see:
- **[Field Mapping Documentation](docs/FIELD_MAPPING.md)** - Comprehensive mapping reference for all Gemara Layer-3 to Ampel policy transformations

## Output Format

### Single Policy Output (Default)

The output follows the official [Ampel Policy API format](https://github.com/carabiner-dev/policy/tree/main/api/v1):

```json
{
  "id": "policy-001",
  "meta": {
    "runtime": "cel@v14.0",
    "description": "Verify software supply chain security",
    "assert_mode": "AND",
    "version": 1
  },
  "context": {
    "builder-id": {
      "type": "string",
      "required": false,
      "value": "https://github.com/actions/runner",
      "default": "https://github.com/actions/runner",
      "description": "Expected SLSA builder ID"
    }
  },
  "tenets": [
    {
      "id": "SC-01.01-slsa-prov-check-0",
      "title": "Verify SLSA provenance",
      "runtime": "cel@v14.0",
      "predicates": {
        "types": [
          "https://slsa.dev/provenance/v1"
        ]
      },
      "code": "attestation.predicateType == \"https://slsa.dev/provenance/v1\" && attestation.predicate.builder.id == context[\"builder-id\"]"
    }
  ]
}
```

**Key Structure:**
- **`id`**: Policy identifier
- **`meta`**: Policy metadata (runtime, description, assert_mode, version)
- **`context`**: Runtime parameters from Gemara assessment plan parameters
- **`tenets`**: Array of verification checks with CEL expressions

For detailed field descriptions, see [Field Mapping Documentation](docs/FIELD_MAPPING.md).

### PolicySet Output (with `--policyset` flag)

```json
{
  "id": "supply-chain-security-policyset",
  "meta": {
    "description": "Verify software supply chain security",
    "version": 1
  },
  "policies": [
    {
      "id": "policy-001",
      "meta": {
        "runtime": "cel@v14.0",
        "description": "Main supply chain policy",
        "assert_mode": "AND",
        "version": 1
      },
      "context": {
        "builder-id": {
          "type": "string",
          "required": false,
          "value": "https://github.com/actions/runner",
          "default": "https://github.com/actions/runner",
          "description": "Expected SLSA builder ID"
        }
      },
      "tenets": [
        {
          "id": "SC-01.01-slsa-prov-check-0",
          "title": "Verify SLSA provenance",
          "runtime": "cel@v14.0",
          "predicates": {
            "types": ["https://slsa.dev/provenance/v1"]
          },
          "code": "attestation.predicateType == \"https://slsa.dev/provenance/v1\" && attestation.predicate.builder.id == context[\"builder-id\"]"
        }
      ]
    },
    {
      "id": "imported-policy-id",
      "source": {
        "id": "imported-policy-id",
        "location": {
          "uri": "git+https://github.com/org/repo#path/to/policy.json"
        }
      }
    }
  ]
}
```

**PolicySet Structure:**
- **Inline policies**: Include full `tenets` array with CEL code
- **External references**: Use `source` field with `PolicyRef` containing `id` and `location.uri`
- Policies without tenets are treated as external references
- Each policy in the set follows the same structure as single policy output
- **Note:** `meta.version` is an integer (int64), parsed from version strings (e.g., "1.0.0" → 1)

## CEL Code Generation

### Implementation (Automated)

The Go implementation automatically generates CEL code based on evidence requirements and parameters:

**Supported Templates:**
- **SLSA Provenance Builder**: Checks builder identity
- **SLSA Provenance Materials**: Validates material digests
- **SLSA Build Type**: Verifies build type
- **Vulnerability Scanning**: Validates scan results and thresholds

**Example Generated CEL:**
```cel
attestation.predicateType == "https://slsa.dev/provenance/v1" &&
attestation.predicate.builder.id == "https://github.com/actions/runner"
```

**Parameter Mapping:**
Parameters from Gemara assessment plans are mapped to Policy.Context as ContextVal entries. CEL expressions reference these values using `context["param-id"]` syntax.

For detailed parameter mapping documentation, including handling of multi-value parameters, runtime-only parameters, and CEL integration, see:
- **[Parameter to Context Mapping](docs/FIELD_MAPPING.md#parameter-to-context-mapping)** - Complete parameter transformation reference


## Testing

Test data is available in the `test_data/` directory:

```bash
# Test Go implementation
bin/ampel_export test_data/gemara-policy-with-params.yaml -output /tmp/test-output.json
```

## Using Generated Policies

After generation, test your Ampel policy with the Ampel policy engine:

```bash
# Verify with Ampel
ampel verify \
  --policy output.json \
  --subject-file myapp \
  --attestation-bundle attestations.jsonl
```

## CEL Resources

The generated policies use CEL (Common Expression Language) for evaluation:
- [CEL Language Definition](https://cel.dev/)
- [Ampel Policy Guide](https://github.com/carabiner-dev/ampel/blob/main/docs/03-ampel-policy-guide.md)
- [Ampel Policy Examples](https://github.com/carabiner-dev/policies)

### Common Attestation Types

Reference for common attestation predicate types:
- **SLSA Provenance v1**: `https://slsa.dev/provenance/v1`
- **In-Toto Statement v1**: `https://in-toto.io/Statement/v1`
- **OpenVEX**: `https://openvex.dev/ns/v0.2.0`

## For More Information

About Gemara:
- [Gemara Documentation](https://gemara.openssf.org/)
- [Gemara Go Library](https://github.com/gemaraproj/go-gemara)

About Ampel:
- [Ampel Policy Engine](https://github.com/carabiner-dev/ampel)
- [Ampel Policy API v1](https://github.com/carabiner-dev/policy/tree/main/api/v1) - Official policy format specification
- [Ampel Policies Repository](https://github.com/carabiner-dev/policies)
