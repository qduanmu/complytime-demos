# Field Mapping: Gemara Layer-3 to Ampel Policy

This document describes the complete field mapping from Gemara Layer-3 policy documents to Ampel verification policies.

**Schema Versions:**
- Gemara: v0.18.0 (github.com/ossf/gemara)
- Ampel: github.com/carabiner-dev/ampel
- Ampel Policy Framework: github.com/carabiner-dev/policy

## Overview

Gemara Layer-3 policies are organization-specific governance documents that define risk-informed rules. Ampel policies are supply chain verification policies that use CEL (Common Expression Language) to verify in-toto attestations.

## Top-Level Policy Mapping

### Single Policy Transformation

| Gemara Field | Ampel Field | Transformation | Notes |
|--------------|-------------|----------------|-------|
| `title` | `name` | Direct copy | Policy identifier |
| `metadata.description` | `description` | Direct copy | Policy purpose |
| `metadata.version` | `version` | Direct copy | Semantic version |
| N/A | `rule` | Default: `"all(tenets)"` | Overall evaluation rule |
| `adherence.assessment-plans[]` | `tenets[]` | Transform (see below) | One-to-many mapping |
| `imports.policies[]` | `imports[]` | Direct copy as string array | Policy references (deprecated in favor of PolicySet) |
| Multiple fields | `metadata{}` | Aggregate (see below) | Flattened metadata map |

### PolicySet Structure

When transforming multiple policies or policies with imports, an Ampel **PolicySet** is generated:

| Gemara Source | PolicySet Field | Transformation | Notes |
|---------------|-----------------|----------------|-------|
| Custom or policy metadata | `name` | Configurable or from main policy | PolicySet identifier |
| Custom or policy metadata | `description` | Configurable or from main policy | PolicySet description |
| Custom or policy metadata | `version` | Configurable or from main policy | PolicySet version |
| Custom | `metadata{}` | Optional key-value pairs | Additional metadata |
| Policy(ies) + imports | `policies[]` | Array of PolicyReference | Contains inline and/or external policies |

### PolicyReference Structure

| PolicyReference Field | Type | Description |
|----------------------|------|-------------|
| `id` | string | Policy identifier within the set |
| `policy` | AmpelPolicy (optional) | Inline policy definition |
| `source.location.uri` | string (optional) | External policy URI (e.g., `git+https://github.com/org/repo#path/to/policy.json`) |
| `meta` | PolicyMeta (optional) | Policy metadata |

**PolicyMeta Fields:**
| Field | Description |
|-------|-------------|
| `controls[]` | Array of ControlReference (framework, class, id) |
| `enforce` | Enforcement mode: "ON", "OFF", "WARN" |
| `additionalMetadata` | Additional key-value metadata |

**ControlReference Fields:**
| Field | Description |
|-------|-------------|
| `framework` | Compliance framework name (e.g., "SLSA", "NIST") |
| `class` | Category within framework (e.g., "BUILD") |
| `id` | Control identifier (e.g., "LEVEL_3") |

## Metadata Field Mapping

Gemara metadata and contact information is flattened into the Ampel `metadata` map:

| Gemara Field | Ampel Metadata Key | Example Value |
|--------------|-------------------|---------------|
| `metadata.id` | `policy-id` | `"policy-001"` |
| `metadata.author.name` | `author` | `"Security Team"` |
| `metadata.author.id` | `author-id` | `"security-team"` (only if non-empty) |
| `contacts.responsible[].name` | `responsible` | `"IT Director, Compliance Officer"` (comma-separated) |
| `contacts.accountable[].name` | `accountable` | `"CISO"` (comma-separated) |
| `scope.in.technologies[]` | `scope-technologies` | `"Cloud Computing, Web Applications"` (comma-separated) |
| `scope.in.geopolitical[]` | `scope-regions` | `"United States, European Union"` (comma-separated) |
| `imports.catalogs[].reference-id` | `catalog-references` | `"NIST-800-53, ISO-27001"` (comma-separated) |
| `imports.guidance[].reference-id` | `guidance-references` | `"CIS-CONTROLS"` (comma-separated) |

**Contact Fields:**
- All contact types (Responsible, Accountable, Consulted, Informed) use the `name` field from the `Contact` struct
- Multiple contacts are concatenated with comma-and-space separators
- Only Responsible and Accountable are mapped; Consulted and Informed are excluded (see Fields Not Mapped section)

**Scope Dimensions Available (but not all mapped):**
- `technologies[]`: Technology categories or services
- `geopolitical[]`: Geopolitical regions
- `sensitivity[]`: Data classification levels (not mapped to metadata, only used in CEL filters)
- `users[]`: User roles (not mapped)
- `groups[]`: User groups (not mapped)

## Assessment Plan to Tenet Mapping

Each **automated** evaluation method in an assessment plan generates one Ampel tenet. Only methods with type `"automated"`, `"gate"`, `"behavioral"`, or `"autoremediation"` are mapped.

### Tenet Identification

| Gemara Field | Ampel Field | Transformation |
|--------------|-------------|----------------|
| `assessment-plans[].requirement-id` + `assessment-plans[].id` + method index | `tenets[].id` | Format: `"{requirement-id}-{plan-id}-{method-index}"` |
| `assessment-plans[].evaluation-methods[].description` | `tenets[].name` | Direct copy, or generated from `evidence-requirements` if empty |
| `assessment-plans[].evidence-requirements` + catalog lookup | `tenets[].description` | Combined: catalog text + " - " + evidence requirements |

**Tenet ID Generation:**
The method index starts at 0 and only counts **automated** methods (manual methods are skipped).

**Example:**
```yaml
# Gemara
requirement-id: "SC-01.01"
id: "slsa-check"
# Method index: 0 (first automated method)

# Ampel
id: "SC-01.01-slsa-check-0"
```

### Tenet CEL Code Generation

The `code` field contains a CEL expression generated from multiple Gemara fields:

| Gemara Source | CEL Component | Example |
|---------------|---------------|---------|
| `evidence-requirements` (keyword matching) | Predicate type check | `attestation.predicateType == "https://slsa.dev/provenance/v1"` |
| `evidence-requirements` (pattern matching) | Specific field checks | `attestation.predicate.builder.id == "..."` |
| `parameters[].accepted-values[]` | Value constraints | Builder ID from parameters |
| `scope.in.*` (if scope filters enabled) | Scope filters | `subject.type in ["cloud-app"]` |

### Attestation Types

| Gemara Field | Ampel Field | Transformation |
|--------------|-------------|----------------|
| Inferred from `evidence-requirements` | `tenets[].attestationTypes[]` | List of predicate type URLs |

### Parameters

| Gemara Field | Ampel Field | Transformation |
|--------------|-------------|----------------|
| `parameters[].id` | `tenets[].parameters.{id}` | Key in parameters map |
| `parameters[].accepted-values[0]` | `tenets[].parameters.{id}` value | First accepted value used as default |

**Note:** Parameter `label` and `description` fields are not mapped. Multiple `accepted-values` are used in CEL template generation.

## Evaluation Method Filtering

Only certain evaluation method types are converted to automated tenets:

| Method Type | Included in Ampel? | Rationale |
|-------------|-------------------|-----------|
| `automated` | ✅ Yes | Directly automatable with CEL |
| `gate` | ✅ Yes | Pre-deployment checks |
| `behavioral` | ✅ Yes | Runtime verification |
| `autoremediation` | ✅ Yes | Post-verification actions |
| `manual` | ❌ No | Cannot be automated |

## Scope to CEL Filter Mapping

Scope dimensions can be converted to CEL filters that are prepended to tenet verification code:

### Supported Scope Dimensions

| Gemara Scope Dimension | CEL Filter Pattern | Example | Normalization |
|------------------------|-------------------|---------|---------------|
| `scope.in.technologies[]` | `subject.type in [...]` | `subject.type in ["cloud-computing", "web-applications"]` | Lowercase, spaces→hyphens |
| `scope.in.geopolitical[]` | `subject.annotations.region in [...]` | `subject.annotations.region in ["us", "eu"]` | Region codes (see below) |
| `scope.in.sensitivity[]` | `subject.annotations.classification in [...]` | `subject.annotations.classification in ["confidential", "secret"]` | Lowercase |
| `scope.in.groups[]` | `subject.annotations.group in [...]` | `subject.annotations.group in ["engineering"]` | No normalization |

**Note:** The `scope.in.users[]` dimension is **not** currently mapped to CEL filters.

### Normalization Rules

| Dimension | Normalization | Examples |
|-----------|---------------|----------|
| **technologies** | Lowercase, spaces→hyphens | `"Cloud Computing"` → `"cloud-computing"` |
| **geopolitical** | ISO-style codes | `"United States"` → `"us"`, `"European Union"` → `"eu"`, `"Canada"` → `"ca"`, `"United Kingdom"` → `"uk"` |
| **sensitivity** | Lowercase | `"Confidential"` → `"confidential"` |
| **groups** | No normalization | Used as-is |

## Fields Not Mapped

The following Gemara Layer-3 fields are **not mapped** to Ampel policies:

### Policy-Level Fields

| Gemara Field | Reason |
|--------------|--------|
| `implementation-plan` | Ampel focuses on verification, not implementation timelines or rollout schedules |
| `implementation-plan.notification-process` | Implementation detail, not verification logic |
| `implementation-plan.evaluation-timeline` | Timeline is organizational, not technical verification |
| `implementation-plan.enforcement-timeline` | Timeline is organizational, not technical verification |
| `risks` | Risk management is policy-level context, not verification logic |
| `risks.mitigated[]` | Risk mappings are organizational context |
| `risks.accepted[]` | Risk acceptance is organizational decision, not technical verification |
| `adherence.evaluation-methods` (top-level) | Only assessment-plan-specific methods are transformed |
| `adherence.enforcement-methods[]` | Ampel doesn't model enforcement actions or remediation workflows |
| `adherence.non-compliance` | Non-compliance handling is organizational policy, not verification rule |

### Contact Fields

| Gemara Field | Reason |
|--------------|--------|
| `contacts.consulted[]` | Not directly relevant to automated verification; organizational context only |
| `contacts.informed[]` | Not directly relevant to automated verification; organizational context only |

### Scope Fields

| Gemara Field | Reason |
|--------------|--------|
| `scope.out` | Ampel uses positive assertions (what to verify); exclusions are not modeled |
| `scope.in.users[]` | Not currently mapped to CEL filters (may be added in future versions) |

### Metadata Fields

| Gemara Field | Reason |
|--------------|--------|
| `metadata.date` | Not preserved in Ampel policy metadata |
| `metadata.draft` | Status flag not relevant to runtime verification |
| `metadata.lexicon` | Terminology reference not used in verification |
| `metadata.mapping-references[]` | Not transformed (may contain catalog references that are flattened) |
| `metadata.applicability-categories[]` | Not used in verification logic |
| `metadata.author.type` | Only name and id are preserved |
| `metadata.author.version` | Only name and id are preserved |
| `metadata.author.description` | Only name and id are preserved |
| `metadata.author.uri` | Only name and id are preserved |
| `metadata.author.contact` | Only name and id are preserved |

### Import Fields

| Gemara Field | Reason |
|--------------|--------|
| `imports.catalogs[].exclusions[]` | Exclusions are processed during policy authoring, not verification |
| `imports.catalogs[].constraints[]` | Constraints modify requirements but aren't directly mapped |
| `imports.catalogs[].assessment-requirement-modifications[]` | Modifications are applied during transformation, not preserved |
| `imports.guidance[].exclusions[]` | Exclusions are processed during policy authoring |
| `imports.guidance[].constraints[]` | Constraints modify guidelines but aren't directly mapped |

### Assessment Plan Fields

| Gemara Field | Reason |
|--------------|--------|
| `assessment-plans[].frequency` | Assessment schedule is execution context, not verification logic |
| `evaluation-methods[].actor` | Execution context (who performs assessment), not verification rule |

### Parameter Fields

| Gemara Field | Reason |
|--------------|--------|
| `parameters[].label` | Human-readable labels not needed in runtime verification |
| `parameters[].description` | Descriptions not needed in runtime verification |

**Note:** Many of these fields contain valuable organizational context and governance information, but they are not directly translated into verification rules.

## Evidence Requirements to CEL Template Mapping

CEL code generation is based on keyword detection in the `evidence-requirements` field:

| Evidence Keywords | Attestation Type Inferred | Template Category |
|-------------------|---------------------------|-------------------|
| "slsa", "provenance" | `https://slsa.dev/provenance/v1` | SLSA Provenance |
| "sbom", "spdx" | `https://spdx.dev/Document` | SPDX SBOM |
| "cyclonedx" | `https://cyclonedx.org/bom` | CycloneDX SBOM |
| "vulnerability", "cve" | `https://in-toto.io/Statement/v0.1` | Vulnerability Scan |

**Specific Template Selection:**
- "builder" → Builder identity verification
- "materials" → Materials verification
- "buildtype" → Build type verification
- "critical", "no critical" → No critical vulnerabilities
- "threshold" → Vulnerability threshold checks
- "scanner" → Scanner vendor verification

## Field Cardinality

| Mapping | Cardinality | Notes |
|---------|-------------|-------|
| Policy → Ampel Policy | 1:1 | One Gemara policy creates one Ampel policy |
| Assessment Plan → Tenet | 1:N | One plan can create multiple tenets (one per automated method) |
| Evaluation Method → Tenet | 1:1 or 1:0 | Only automated methods create tenets |
| Parameter → Tenet Parameter | 1:1 | Direct mapping |
| Evidence Requirement → CEL Code | 1:1 | Transformed via templates |
| Scope Dimension → CEL Filter | 1:1 | Each dimension creates one filter |

## References

### Schemas and Specifications

- **Gemara Project**: https://github.com/gemaraproj/gemara
  - Layer-3 Schema: https://github.com/gemaraproj/gemara/blob/main/schemas/layer-3.cue
  - Go Package (v0.18.0): github.com/ossf/gemara
- **Ampel Policy Framework**: https://github.com/carabiner-dev/policy
- **Ampel Verification**: https://github.com/carabiner-dev/ampel
- **in-toto Attestation Framework**: https://github.com/in-toto/attestation
  - Attestation Spec: https://github.com/in-toto/attestation/tree/main/spec
- **SLSA (Supply chain Levels for Software Artifacts)**:
  - SLSA Framework: https://slsa.dev
  - SLSA Provenance v1.0: https://slsa.dev/provenance/v1
- **Common Expression Language (CEL)**: https://github.com/google/cel-spec
