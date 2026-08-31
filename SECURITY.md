# Security Policy

DDC-OS is pre-alpha research software and must not be treated as production security infrastructure.

## Reporting

Do not publish credentials, private DDC material, confidential evidence, exploit payloads, or other restricted information in a public issue or pull request.

For a potentially sensitive vulnerability, use a private repository/security reporting channel when one is available. If no private channel is visible, open a public issue containing only a minimal non-sensitive request for maintainer contact; do not include the vulnerability details there.

## Public issue content

Public reports may safely include:

- affected public version/commit;
- observable non-sensitive symptoms;
- expected behavior;
- minimal reproduction information that does not create avoidable exploitation risk;
- whether the issue concerns correctness, resource containment, provenance, fallback, or authority boundaries.

## DDC-OS security invariants

Performance work does not override these invariants:

- no optimization may expand authority;
- stale or corrupt reusable state is a cache miss, not a valid result;
- exact-state provenance is required for v0.1 reuse;
- speculative computation does not gain external commit authority;
- resource ceilings remain enforceable during optimization;
- kernel-affecting experiments require a tested fallback path;
- a speedup with semantic mismatch is a failure.

See `docs/DDC_GATES.md` and `docs/PUBLIC_BOUNDARY.md` for the public engineering contract.
