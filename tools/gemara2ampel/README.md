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
bin/ampel_export test_data/ampel-test-policy.yaml -output my-policy.json

# Generate PolicySet with scope filters
bin/ampel_export test_data/ampel-test-policy.yaml -policyset -scope-filters -output policyset.json
```

### Features
- **Full Gemara Layer 3 schema support** via `github.com/gemaraproj/go-gemara`
- **Official Ampel API compliance** - Matches the official Ampel Policy API format from `github.com/carabiner-dev/policy/api/v1`
  - Uses snake_case field names (e.g., `assert_mode`)
  - CEL runtime version `cel@v14.0`
  - Structured Output objects with CEL code expressions
  - PredicateSpec for attestation type filtering
- **Workspace mode** - Preserves manual CEL edits on policy regeneration
- **Smart parameter handling** - Parameters mapped to Output objects with CEL code
- **Catalog enrichment** to populate tenet descriptions
- **Scope-based CEL filter generation**
- **PolicySet generation** with import handling (inline and external references)
- **Template-based CEL code generation** with PascalCase parameter support
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
- Parameters → Output objects with CEL code
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
      "code": "attestation.predicateType == \"https://slsa.dev/provenance/v1\" && attestation.predicate.builder.id == \"https://github.com/actions/runner\"",
      "outputs": {
        "builder-id": {
          "code": "context.builder-id"
        }
      }
    }
  ]
}
```

**Key Structure Notes:**
- **`id`**: Policy identifier (from Gemara `policy.Metadata.Id`)
- **`meta`**: Contains policy metadata
  - **`runtime`**: CEL runtime version (default: "cel@v14.0")
  - **`description`**: Policy description
  - **`assert_mode`**: Either "AND" (all tenets must pass) or "OR" (any tenet can pass) - note snake_case
  - **`version`**: Integer version (parsed from Gemara version string, e.g., "1.0.0" → 1)
  - **`enforce`**: Optional enforcement mode ("ON", "OFF", "WARN")
- **`tenets`**: Array of verification tenets
  - **`id`**: Unique tenet identifier
  - **`title`**: Human-readable tenet name
  - **`runtime`**: Runtime identifier (inherits from policy if not set)
  - **`predicates`**: Specifies which attestation types this tenet evaluates
  - **`code`**: CEL expression for verification
  - **`outputs`**: Map of Output objects with CEL code to extract values

### PolicySet Output (with `--policyset` flag)

```json
{
  "id": "supply-chain-security-policyset",
  "meta": {
    "description": "Verify software supply chain security",
    "version": "1.0.0"
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
      "tenets": [
        {
          "id": "SC-01.01-slsa-prov-check-0",
          "title": "Verify SLSA provenance",
          "runtime": "cel@v14.0",
          "predicates": {
            "types": ["https://slsa.dev/provenance/v1"]
          },
          "code": "attestation.predicateType == \"https://slsa.dev/provenance/v1\"",
          "outputs": {
            "builder-id": {
              "code": "context.builder-id"
            }
          }
        }
      ]
    },
    {
      "id": "imported-policy-id",
      "source": {
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
- **External references**: Use `source.location.uri` to reference external policies
- Policies without tenets are treated as external references
- Each policy in the set follows the same structure as single policy output

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
Parameters from Gemara assessment plans are mapped to Output objects that reference context values:
```json
"outputs": {
  "builder-id": {
    "code": "context.builder-id"
  }
}
```
The `code` field contains a CEL expression that accesses the parameter value from the runtime context.


## Testing

Test data is available in the `test_data/` directory:

```bash
# Test Go implementation
bin/ampel_export test_data/ampel-test-policy.yaml -output /tmp/test-output.json
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

## Documentation

For comprehensive documentation, see:
- **[Field Mapping Documentation](docs/FIELD_MAPPING.md)** - Complete mapping reference

### CEL Resources

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
