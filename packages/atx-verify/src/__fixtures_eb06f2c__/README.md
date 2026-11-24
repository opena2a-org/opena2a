# Conformance fixtures 22 and 23

These two files are verbatim copies of `fixtures/` in
[opena2a-standards/atx-conformance](https://github.com/opena2a-standards/atx-conformance)
at `eb06f2c76a264a3abf999e91e0502dba594e3495`, the suite's 23-fixture ref:

- `v1_1-hybrid-mldsa-tampered.json`: pinned REJECT `SIGNATURE_INVALID`
- `v1_1-no-transparency-log-index.json`: pinned ACCEPT

The other 21 fixtures are in `../__fixtures__/`, at the ref CI pins
(`ATX_CONFORMANCE_REF`, `d2b8376`). CI byte-compares that directory against
the pinned suite in both directions, so these two files live here, not there,
until CI moves its pin. `conformance.test.ts` replays both directories and
asserts 23 of 23 (opena2a-standards/atx-spec#46).
