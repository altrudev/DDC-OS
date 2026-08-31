# DDC-OS Public Boundary

DDC-OS is intended to be developed in public without requiring disclosure of proprietary DDC methodology.

## Public by default

The repository may publish:

- operating-system architecture;
- compute identity formats;
- shared-state and delta representations;
- public safety invariants;
- benchmark definitions and results;
- test vectors;
- resource-accounting models;
- scheduler/compositor integration code;
- compatibility layers;
- externally observable governor inputs and decisions;
- failure, fallback, and rollback behavior.

## Out of scope for disclosure

The repository must not require or casually include:

- proprietary DDC scoring rules;
- confidential assurance heuristics;
- private prompt or reasoning material;
- restricted evidence or customer material;
- unpublished vulnerability details;
- secrets, credentials, tokens, keys, or private infrastructure configuration;
- private datasets used to tune DDC decisions;
- internal rules whose publication would defeat a security boundary.

## Contract, not disclosure

DDC-OS components interact with governance through a public contract. A candidate optimization supplies observable facts such as:

- exact input/dependency identity;
- baseline and candidate authority;
- resource bounds;
- semantic-equivalence evidence;
- commit state;
- provenance binding.

The public boundary returns a decision such as accept/reject plus a public reason class. The mechanism used to produce additional private assurance may remain outside this repository.

## No implied authority

A request to optimize, benchmark, debug, document, publish, or make DDC-OS more transparent does **not** authorize disclosure of information outside this public boundary.

Likewise, an optimization that improves performance does not gain new permissions merely because those permissions would make it faster.

## Contribution rule

A contribution that depends on non-public DDC material must be redesigned around a public interface or kept outside this repository. Public DDC-OS must remain buildable, testable, and reviewable without private DDC internals.
