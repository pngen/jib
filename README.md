# Jurisdictional Intelligence Boundary (JIB)

Sovereign containment and boundary enforcement for intelligence execution, preventing unauthorized cross-domain activity without exception.

## Overview

JIB is a systems-level framework that defines where intelligence (models, agents, workflows) is allowed to exist, execute, and act.

It operates below orchestration and above infrastructure, binding execution environments to territorial and legal reality through hard constraints rather than policy interpretation.

## Architecture

<pre>
┌─────────────────────────────────────────────────────────────────────┐
│                  ResearchGradeBoundaryEnforcer                      │
│  (Integrates all subsystems for production-grade enforcement)       │
└─────────────────────────────────────────────────────────────────────┘
         │
         ├──────────────────────────────────────────────────────────┐
         ▼                                                          │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐  │
│ BoundaryEnforcer│    │ TemporalBoundary │    │  Distributed    │  │
│                 │    │ Manager          │    │  Enforcer       │  │
│ - Jurisdictions │    │                  │    │                 │  │
│ - Domains       │    │ - ValidFrom/Until│    │ - PBFT Consensus│  │
│ - Bindings      │    │ - GracePeriods   │    │ - Quorum Voting │  │
│ - Boundaries    │    │ - Expiry Hooks   │    │ - Decision Log  │  │
└────────┬────────┘    └────────┬─────────┘    └────────┬────────┘  │
         │                      │                       │           │
         ▼                      ▼                       ▼           │
┌─────────────────────────────────────────────────────────────────┐ │
│                     Cryptographic Layer                         │ │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐  │ │
│  │ KeyManager  │  │ MerkleTree  │  │ CryptographicBinding    │  │ │
│  │ (Ed25519)   │  │ (Audit Log) │  │ (Signatures + Hashes)   │  │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘  │ │
└─────────────────────────────────────────────────────────────────┘ │
         │                                                          │
         ▼                                                          │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐  │
│ InvariantChecker│    │ DataFlowTracker  │    │ PolicyManager   │◄─┘
│                 │    │                  │    │                 │
│ - I1: Binding   │    │ - ProvenanceGraph│    │ - PolicyNodes   │
│ - I2: Explicit  │    │ - FlowRecords    │    │ - BoundaryExprs │
│ - I4: FailClosed│    │ - Crossings      │    │ - Simulation    │
│ - I5: Auditable │    │ - Compliance     │    │ - Conflicts     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                      │                       │
         ▼                      ▼                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                      IntegrationAdapter                         │
│         (External system interface + proof emission)            │
└─────────────────────────────────────────────────────────────────┘
</pre>

## Components

### Boundary Enforcer  
Enforces jurisdictional boundaries at runtime. Artifacts are bound to jurisdictions at compile/deploy time via cryptographic bindings. No runtime boundary escalation is permitted.

### Boundary Resolver  
Resolves conflicts and overlaps in jurisdictional claims. Conflicting claims fail closed. Overlapping jurisdictions are resolved deterministically. Missing bindings are denied by default.

### Proof Generator  
Generates machine-verifiable audit trails for all boundary decisions. Proofs are reconstructable without runtime introspection, with full context included in the audit trail.

### Integration Adapter  
Interfaces with execution systems and governance layers including deterministic execution systems, authority compilers, zero-trust sandboxes, and cost attribution systems.

### Core Types  
Formal definitions of the primitive structures: Jurisdiction, ExecutionDomain, Boundary, JurisdictionalClaim, JurisdictionalBinding, and BoundaryProof.

## Build

```bash
go build
```

## Test

```bash
go test ./tests/... -v
```

## Run

```bash
./jib # Linux/macOS

.\jib.exe # Windows
```

## Design Principles

1. **Hard Boundaries** - Jurisdictional constraints are absolute, not advisory. No silent cross-jurisdiction execution.
2. **Enforcement-Oriented** - JIB prevents execution, does not observe it. No trust-based boundary relaxation.
3. **Deterministic** - All behavior is predictable and consistent. No runtime jurisdiction mutation.
4. **Auditable** - Every decision generates a verifiable proof.
5. **Composable** - Integrates cleanly with existing governance systems.

## Requirements

- Go 1.21+