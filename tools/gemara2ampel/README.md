# Gemara to Ampel Converter

This directory contains tools for converting Gemara Layer 3 policy files to Ampel verification policy format.

## Overview

The `gemara2ampel` tools convert Gemara Layer 3 policies (organizational governance policies) into Ampel verification policies. Gemara policies define *what* controls are required, while Ampel policies define *how* to verify compliance through attestation checking.

### About Ampel

[Ampel](https://github.com/carabiner-dev/ampel) is "The Amazing Multipurpose Policy Engine (and L)" - a lightweight supply chain policy engine designed to verify unforgeable metadata captured in signed attestations throughout the software development lifecycle.

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
# Output to stdout
bin/ampel_export <policy.yaml>

# Output to file
bin/ampel_export <policy.yaml> -output <output.json>

# With catalog enrichment
bin/ampel_export <policy.yaml> -catalog <catalog.yaml> -output <output.json>

# With scope filters
bin/ampel_export <policy.yaml> -scope-filters -output <output.json>

# Generate PolicySet with imports
bin/ampel_export <policy.yaml> -policyset -output <output.json>
```

### Command-Line Flags

| Flag | Description | Default |
|------|-------------|---------|
| `-output`, `-o` | Output file path | stdout |
| `-catalog` | Catalog file for enriching policy details | - |
| `-scope-filters` | Include scope-based CEL filters in tenets | false |
| `-policyset` | Generate a PolicySet with imports as external references | false |
| `-policyset-name` | Name for the PolicySet (only used with -policyset) | - |
| `-policyset-description` | Description for the PolicySet | - |
| `-policyset-version` | Version for the PolicySet | - |

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
- Full Gemara Layer 3 schema support via `github.com/ossf/gemara`
- Catalog enrichment to populate tenet descriptions
- Scope-based CEL filter generation
- PolicySet generation with import handling
- Template-based CEL code generation
- Automatic attestation type inference

### Dependencies
The Go version uses the following dependencies:
- `github.com/ossf/gemara v0.18.0` - Gemara schema definitions
- `github.com/goccy/go-yaml v1.19.1` - YAML parsing

## Field Mappings

For detailed field mapping documentation, see:
- **[Field Mapping Documentation](docs/FIELD_MAPPING.md)** - Comprehensive mapping reference for all Gemara Layer-3 to Ampel policy transformations

## Output Format

### Single Policy Output (Default)

```json
{
  "name": "Supply Chain Security Policy",
  "description": "Verify software supply chain security",
  "version": "1.0.0",
  "metadata": {
    "policy-id": "policy-001",
    "author": "Security Team",
    "author-id": "security-team",
    "responsible": "DevOps Manager",
    "accountable": "CISO",
    "scope-technologies": "Container Images",
    "scope-regions": "United States",
    "catalog-references": "SLSA-CONTROLS"
  },
  "imports": [],
  "tenets": [
    {
      "id": "SC-01.01-slsa-prov-check-0",
      "name": "Verify SLSA provenance",
      "description": "SLSA provenance with trusted builder",
      "code": "attestation.predicateType == \"https://slsa.dev/provenance/v1\" && attestation.predicate.builder.id == \"https://github.com/actions/runner\"",
      "attestationTypes": [
        "https://slsa.dev/provenance/v1"
      ],
      "parameters": {
        "builder-id": "https://github.com/actions/runner"
      }
    }
  ],
  "rule": "all(tenets)"
}
```

### PolicySet Output (with `-policyset` flag)

```json
{
  "name": "Supply Chain Security Policy",
  "description": "Verify software supply chain security",
  "version": "1.0.0",
  "metadata": { ... },
  "policies": [
    {
      "id": "policy-001",
      "policy": {
        "name": "Supply Chain Security Policy",
        "tenets": [ ... ],
        "rule": "all(tenets)"
      }
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

## CEL Code Generation

### Implementation(Automated)

The Go implementation automatically generates CEL code based on evidence requirements and parameters:

**Supported Templates:**
- **SLSA Provenance Builder**: Checks builder identity
- **SLSA Provenance Materials**: Validates material digests
- **SLSA Build Type**: Verifies build type
- **SBOM Presence**: Checks for SPDX or CycloneDX SBOMs
- **Vulnerability Scanning**: Validates scan results and thresholds

**Example Generated CEL:**
```cel
attestation.predicateType == "https://slsa.dev/provenance/v1" &&
attestation.predicate.builder.id == "https://github.com/actions/runner"
```


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
- **SPDX SBOM**: `https://spdx.dev/Document`
- **CycloneDX SBOM**: `https://cyclonedx.org/bom`
- **OpenVEX**: `https://openvex.dev/ns/v0.2.0`

## For More Information

About Gemara:
- [Gemara Documentation](https://gemara.openssf.org/)
- [Gemara GitHub](https://github.com/ossf/gemara/)
- [Gemara Layer 3 Schema](https://github.com/ossf/gemara/blob/main/schemas/layer-3.cue)

About Ampel:
- [Ampel Policy Engine](https://github.com/carabiner-dev/ampel)
- [Ampel Policies Repository](https://github.com/carabiner-dev/policies)
