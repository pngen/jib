# Jurisdictional Intelligence Boundary (JIB)

Sovereign containment and boundary enforcement for intelligence execution, preventing unauthorized cross-domain activity without exception.

## Overview

JIB is a systems-level framework that defines where intelligence (models, agents, workflows) is allowed to exist, execute, and act.

It operates below orchestration and above infrastructure, binding execution environments to territorial and legal reality through hard constraints rather than policy interpretation.

## Architecture

<pre>
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│   Intelligence  │    │   Execution      │    │   Jurisdiction     │
│   Artifacts     │◄──►│   Domains        │◄──►│   Boundaries       │
│                 │    │                  │    │                    │
└─────────────────┘    └──────────────────┘    └────────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│  Boundary       │    │  Enforcement     │    │   Resolution       │
│  Enforcer       │◄──►│  Engine          │◄──►│   Logic            │
│                 │    │                  │    │                    │
└─────────────────┘    └──────────────────┘    └────────────────────┘
         │                       │                        │
         ▼                       ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌────────────────────┐
│  Integration    │    │  Proof           │    │   Governance       │
│  Adapter        │◄──►│  Generator       │◄──►│   Layer            │
│                 │    │                  │    │                    │
└─────────────────┘    └──────────────────┘    └────────────────────┘
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
go test ./tests/...
```

## Run
```bash
./jib
```

On Windows:
```bash
.\jib.exe
```

## Design Principles
1. **Hard Boundaries** - Jurisdictional constraints are absolute, not advisory. No silent cross-jurisdiction execution.
2. **Enforcement-Oriented** - JIB prevents execution, does not observe it. No trust-based boundary relaxation.
3. **Deterministic** - All behavior is predictable and consistent. No runtime jurisdiction mutation.
4. **Auditable** - Every decision generates a verifiable proof.
5. **Composable** - Integrates cleanly with existing governance systems.

## Requirements
- Go 1.21+
- Cryptographic binding of artifacts to jurisdictions
- Fail-closed on ambiguous or missing jurisdictional clarity
- Machine-verifiable proofs for all decisions