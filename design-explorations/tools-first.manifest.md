# Tools-first exploration

2026-10-09. Interactive design proposal, not a live scan or native implementation.
All three variants use the same six illustrative Tools and policy/decision samples.
The comparison chrome reuses `_template.html`; the previews retain the app's violet
accent and native system typography. No new production design contract is approved.

## Data grounding

Read `docs/domain-language.md`, `docs/architecture.md`, and `docs/positioning.md`.
Sampled `DashboardSnapshot` and the `DashboardModel` self-check fixture in
`src/menu-helper/Sources/MenubarHelper/MainWindow.swift` (around line 2466).
That fixture contains three Detectors, two hardened Tool records, one Gate,
two Secrets, one Authorization Record, and one AWS Doctor issue. It is not a
coherent six-Tool installation; the proposal explicitly labels its scenario as
illustrative instead of presenting this fixture as the user's machine.

| Element | Existing source | Class / count |
| --- | --- | --- |
| Tool identities | Hardeners and built-in integration definitions | Existing concepts; 6 illustrative rows |
| Hardening status | `hardenedTools`, `hardeners` | Existing shape; fixture 2 hardened records; preview 3 installed and 1 configured integration |
| Doctor issue | `doctorIssues` | Real fixture: 1 AWS command-resolution issue |
| npm Hazard | `detectors/npm/detector.md` | Existing check; 1 illustrative finding, not scanned |
| Docker presence with no finding | No unified installed-inventory field established | Aspirational: 1 example; requires passive presence evidence before production |
| Activity | `overviewActivitySlots`, `overviewLatestActivity`, Authorization Records | Existing bounded 24-hour source; all chart values, counts and timestamps illustrative |
| Empty activity | Same bounded history source | 1 illustrative SSH example; unavailable history must not become zero |
| Policies | `secretGates.defaultProtection`, `appPolicies`, denial thresholds | Existing shape; all displayed policies illustrative |
| Tool integration settings | Existing hardener docs and app settings | Existing owners; consolidated presentation proposed |
| Verified Launcher Helpers | Shared Launcher settings | Existing cross-gate authority; linked, never represented as tool-local |
| Why harden? | Docker hardener documentation | Editorial proposal grounded in existing migration and credential boundary |
| npm mitigation | npm Detector documentation | Existing `min-release-age=1` recommendation; not a credential-hardening action |

## Behavior and implementation boundaries

- A: per-tool 24-hour activity strips and a two-column configuration layout.
- B: the selected tool additionally expands recent decisions beneath its row.
- C: compact tools plus a separate selected-tool activity inspector.
- Tool selection, local search/clear, section switching, and explanatory dialogs work.
- Review/configuration buttons explain the intended production flow. They cannot
  install software, mutate policy, read Secrets, run scans, or persist anything.
- Hardening and findings are independent facts. AWS keeps its installed state
  while showing its Doctor issue. A future model must retain every concurrent
  Detector and Doctor finding instead of collapsing them to one exclusive status.
- Global Secret custody, Project Values, scripts, direct/proxy gates, Launcher
  Bundles, shared helpers, and Approval settings remain reachable through
  secondary destinations; their complete screens are outside this concept.
- Production must reuse existing policy mutation and Approval paths, including
  denials, runtime requirements, descendant-rule overrides, and stale-state checks.
- Configured SSH keys require independent gate identity and selection; the
  concept illustrates one key only. No universal policy ladder is introduced.
- Live inventory, loading, stale scans, failure/retry, all findings, long lists,
  and full history pagination remain native implementation work. Do not treat
  the concept's six-item render-all list as the production inventory contract.

No security boundary, authority model, or system invariant changes in this
artifact. No ADR or domain-language change is necessary.

## Verification

Playwright exercised all six tools in each of the three variants, Integration
and History sections, search/no-results/clear, and dialog dismissal with Escape.
The 390px layout had no document-level horizontal overflow. Desktop and narrow
screenshots were inspected. The static premium audit reported no findings in
this new HTML; its overall strict run retains an unrelated actionless-button
finding in the existing `overview-directions.html`. Audit output is at
`/tmp/av-tools-first-audit.json` for this session. No native app build or runtime
security tests were run because no production code changed.
