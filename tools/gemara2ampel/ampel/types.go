// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package ampel

import (
	v1 "github.com/carabiner-dev/policy/api/v1"
	signer "github.com/carabiner-dev/signer/api/v1"
	intoto "github.com/in-toto/attestation/go/v1"
)

// Re-export official Ampel policy types from github.com/carabiner-dev/policy/api/v1

// Policy types
type (
	Policy          = v1.Policy
	PolicyRef       = v1.PolicyRef
	PolicySet       = v1.PolicySet
	PolicySetMeta   = v1.PolicySetMeta
	PolicySetCommon = v1.PolicySetCommon
	PolicyGroup     = v1.PolicyGroup
	PolicyGroupMeta = v1.PolicyGroupMeta
	PolicyGroupRef  = v1.PolicyGroupRef
	PolicyBlock     = v1.PolicyBlock
	PolicyBlockMeta = v1.PolicyBlockMeta
)

// Metadata types
type (
	Meta         = v1.Meta
	Control      = v1.Control
	FrameworkRef = v1.FrameworkRef
)

// Tenet and related types
type (
	Tenet         = v1.Tenet
	PredicateSpec = v1.PredicateSpec
	Output        = v1.Output
	Error         = v1.Error
	Assessment    = v1.Assessment
)

// Context types
type (
	ContextVal = v1.ContextVal
)

// Chain types
// type (
// 	ChainLink        = v1.ChainLink
// 	ChainedPredicate = v1.ChainedPredicate
// 	ChainedOutput    = v1.ChainedOutput
// )

// Transformer type
// type (
// 	Transformer = v1.Transformer
// )

// Identity and resource types
type (
	Identity           = signer.Identity
	ResourceDescriptor = intoto.ResourceDescriptor
)

// Result types
// type (
// 	Result         = v1.Result
// 	ResultSet      = v1.ResultSet
// 	ResultGroup    = v1.ResultGroup
// 	EvalResult     = v1.EvalResult
// 	BlockEvalResult = v1.BlockEvalResult
// 	ChainedSubject = v1.ChainedSubject
// 	ChainedSubjectLink = v1.ChainedSubjectLink
// 	StatementRef   = v1.StatementRef
// 	ResultSetCommon = v1.ResultSetCommon
// )
