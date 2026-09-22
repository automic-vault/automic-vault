# Overview exploration data manifest

This artifact deliberately retains the user-approved mock scenario. It is not a local security scan. Real source shape sampled from `DashboardSnapshot.swift` and `dashboardAuthorityApprovalSelfCheck` fixtures in `MainWindow.swift` (around lines 1920–1995). Those fixtures have 3 detector entries, 2 hardened Tool entries, 2 Secrets, 1 Gate and 1 Doctor issue; they do not substantiate the mock’s six-Tool dataset. User instruction to keep identical content takes precedence over substituting unrelated fixture values.

| Element | Source / field | Class | Count / limitation |
|---|---|---|---|
| Tool names and labels | Prior approved six-Tool mock | Illustrative | 6 in each variant; not a live inventory |
| Installed/hardened state | `DashboardSnapshot.hardenedTools`, `hardeners` | Real source shape; sample values | Fixture: 2 entries, not the mock’s state counts |
| AWS exposure | `detectorFindings` | Illustrative | 1 in mock; sampled fixture has 0 findings |
| Doctor command resolution issue | `doctorIssues` | Real source shape; sample association | 1 fixture issue belongs to AWS; mock associates it with gh |
| Configuration levels | `secretGates.defaultProtection`, `appPolicies` | Real source shape; sample values | Fixture: 1 gate, not a live policy snapshot |
| Healthy installed Tool inventory | No unified field in sampled snapshot | Aspirational presentation/data integration | Mock displays 6; reliable inventory must be verified before implementation |
| Uninstalled monitoring count | Detector catalog vs installed inventory | Aspirational derivation | Mock says 15; not counted on this Mac |
| Last scan | Scan completion state | Illustrative | “Just now” is fixed copy in all 4 previews |
| Secrets | `secrets.account` | Real source shape; sample names | Fixture 2 names; mock 2 different names. No values read |
| Projects | Secret Project Value sources | Existing concept; illustrative grouping | 1 Project / 1 Project Value in mock; not queried |
| Launchers | Gate rules / designated requirements | Existing concept; illustrative grouping | 3 in mock; not a universal allow-list |
| App update | `DashboardModel.availableUpdateVersion` | Sometimes, not queried | 1 illustrative notification; no version asserted |
| What’s new article | No feed identified | Aspirational | 1 illustrative article, no actual link |

All variants include the same findings, six Tools, global Secret names, three Launchers, one Project and two announcements. Variant C presents the Doctor message within the gh panel. Buttons intentionally open a preview-only explanation. Choosing a design does not authorize implementation or security-policy changes.

## Native implementation (2026-09-22)

The user selected A as a structural guideline and authorized native implementation. Overview is the default destination; all existing sidebar sections remain. Projects link to Secrets and have no sidebar section. Bounded summaries replace scrolling within Overview; existing inventory/detail screens retain their normal scrolling.

Live content uses detector findings, hardening records, Doctor issues, Secret counts, Launcher Bundle enrollments, Project Value directories, and the existing update checker. No installed-inventory claim, monitoring count for uninstalled Tools, fabricated news feed, universal Launcher allow-list, or security score is introduced. The mock's Launcher summary maps to the existing Launcher Bundles destination. No authorization or Secret routing behavior changes.

Validation: Swift package build; dashboard search/navigation self-check; optional native renders at 590×480, 590×550, and 980×680 detail-area sizes with an overflowing Tool inventory. Reproduce renders with `AV_OVERVIEW_RENDER_DIR=/tmp src/menu-helper/.build/debug/AutomicVaultMenubar --self-check-dashboard-search`.

### Follow-up refinement

Removed the duplicate content heading (Overview remains in the native toolbar), moved configuration summaries above the inventory, and adjusted row budgets after compact/wide rendering. Hardened rows now come from the same inventory as the sidebar; multiple detectors referencing one hardener no longer inflate the Overview. A regression check covers duplicate detector metadata.

The website checkout contains `/index.json` for the product overview and JSON-LD embedded in `/blog/`, but no standalone blog feed was found; `/blog/index.json` returned 404. The app currently links to the existing blog and introductory article, without presenting those links as a live feed.

### JSON news feed

The website now generates `/blog/index.json` from the blog index's editorial order. Overview fetches it with a bounded, timed HTTPS request and displays at most two same-origin blog links (one at compact sizes). The blog link remains available on network or decoding failures. No local security data is sent with the request.

### Attention ordering, activity, and footer

Doctor-only Tools are included; Tools with Doctor reports or detector findings sort before healthy Tools. Overflow is paginated to preserve the no-scroll layout. Both feed headlines remain visible in compact layouts, with Documentation and GitHub links in the footer. The deployed feed was verified on 2026-09-22.

Each Tool shows recorded authorization requests within 24 hours, not execution counts. A `+` marks a lower-bound count when older history pages remain unloaded; failed history loads show unavailable. Navigation self-checks cover Doctor-only rows, findings-first ordering, and the time window. Native renders verify the compact footer and two headlines fit.
