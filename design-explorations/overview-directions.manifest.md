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
