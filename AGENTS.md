This is a security product. Changes must not make anything less secure. Every
change must be thoroughly considered for security implications before enacting.

Dont rush to fix something without first considering if the issue at hand is
even a bug in a security-first-mindset.

## Canonical Domain Language

`docs/domain-language.md` and `docs/architecture.md` are authoritative across
the endorsed Automic Vault ecosystem. `docs/positioning.md` is the authoritative
translation of that model into user-facing messaging and defers to both.

Before changing product language, security concepts, authorization policy, UI
copy, CLI vocabulary, or public documentation, read all three files. Use their
terms, claims, and security boundaries. Update the domain language before
introducing or renaming a domain concept. Record an architectural decision in
`docs/adr/` when the change alters a security boundary, authority model, or
system invariant.

Endorsed properties must adopt and link to these definitions rather than keep a
competing copy. Persisted values, wire fields, and compatibility flags may keep
legacy names when changing them would break compatibility; user-facing language
must use the canonical term.

## Environment-wrapper Isotopes

Add or change one environment-wrapper Isotope per pull request. Follow
[`docs/adr/0032-positive-secret-routing.md`](docs/adr/0032-positive-secret-routing.md):
review the exact upstream command surface, positively route only invocations
that may need the protected Secret, and cover both Secret routing and macOS
operation classification with focused tests.
