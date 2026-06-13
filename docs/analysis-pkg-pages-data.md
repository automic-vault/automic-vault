# Package Pages Data Analysis

This evaluates [pkg-pages.md](./pkg-pages.md) against the data currently in
the repository as of 2026-05-23.

## Current Data Inventory

The repository already has enough data to generate a useful first catalog:

- `data/combined.json`
  - generated at `2026-05-22T18:54:58.868812+00:00`
  - 8,364 Homebrew formula records
  - 53 Homebrew cask records
  - 348 npm records
  - 22,037 executable-to-provider index entries
  - 72 isotope records
  - 4 package aliases
  - 2 npm install overlays
  - 2 PyPI install overlays
- `../av.db/data/geiger-counter.json`
  - 8,359 Homebrew formula risk classifications
  - category, confidence, level, reasons, and signals
- `../av.db/data/approval-gates/brew/*.yaml`
  - 20 curated approval-gate manifests
  - package descriptions, entrypoints, risky command rules, severities, and
    coverage review dates
- `../radioisotopes/*`
  - radioisotope package directories with manifests and README notes
- `www/pkg/`
  - already generated static HTML package pages
  - current manifest reports 8,783 pages
  - split today as 8,375 brew, 53 cask, 353 npm, and 2 pip pages

The moved generator now lives at `../av.db/scripts/generate-pkg-pages.py`.

## Can Do With Current Data

### URL Structure

Can do now.

The current generator already emits pages under:

```text
/pkg/{provider}/{package}/
```

Provider names currently include `brew`, `cask`, `npm`, and `pip`. The spec
uses `/pkg/pypi/requests/`; the repo currently models that namespace as `pip`.
That needs a canonical naming decision, not new package facts.

### Server-Rendered Static Pages

Can do now.

The generated pages are static HTML under `www/pkg/`. They do not require client
hydration for meaningful page content.

### Unique Title, Meta Description, Canonical

Mostly can do now.

Current pages already have unique title tags, meta descriptions, and canonical
URLs. They do not yet match the spec's install-focused wording, but that is a
generator/content-template issue, not a data gap.

### Hero/Header Basics

Partly can do now.

Available now:

- package name
- ecosystem/provider
- one-line description for Homebrew formulae, casks, and npm records
- last updated / generated freshness
- cask and npm versions

Missing from current formula data:

- latest formula version
- formula homepage
- license
- full dependency list

Those can be fetched from Homebrew formula metadata, but they are not currently
stored in `../av.db/cache/automic-vault/db.json` or `../av.db/cache/automic-vault/combined.json`.

### Install Section

Can do now for basic commands.

Exact baseline commands are derivable from package identity:

- `brew install <formula>`
- `brew install --cask <cask>`
- `npm install -g <package>` or the Nucleus equivalent
- `pip install <package>` or the Nucleus equivalent
- `av install <qualified-package>` when the page is intentionally
  Automic-Vault-first

Additional platform notes, caveats, and post-install behavior are not generally
available as structured data.

### Package Summary

Can do now for most current pages.

Homebrew formulae, casks, and npm records already have short summaries. These
are terse and operational enough to seed the section.

Needs new or enriched data for:

- PyPI beyond the two current overlay records
- richer "common usage" context
- upstream docs links
- distinguishing library packages from CLI packages at scale

### Security / Trust Section

Can do much more with current data than the current generated pages show.

Available now:

- Geiger risk level, category, confidence, reasons, and signals for nearly all
  Homebrew formulae
- curated isotope/radioisotope security justifications and caveats
- approval-gate manifests for 20 important Homebrew packages
- command-rule severities and descriptions for those approval-gated packages

Current generator uses isotope and approval-gate data, but does not appear to
use `../av.db/data/geiger-counter.json`. Using Geiger would immediately make non-isotope
Homebrew pages less thin.

Still needs new data for:

- exact install-script detection
- remote binary download classification for formulae
- signed bottle / provenance statements
- service names and daemon behavior
- shell-profile modification
- privilege requirements
- cask installer/pkg behavior beyond the few cask fields already present
- npm and PyPI lifecycle-script risk

### Executables Section

Partly can do now.

Available now:

- Homebrew formula executable names from `../av.db/cache/automic-vault/db.json` `entries`
  - example: `aws` and `aws_completer` map to `awscli`
  - example: `rg` maps to `ripgrep`
- cask binary source/target entries
- npm records have one executable field
- installed-package runtime info can report actual stub paths for locally
  installed packages

Important generator gap:

`../av.db/cache/automic-vault/db.json` `entries` maps formula executables to plain formula names such as
`awscli`, not qualified keys like `brew:awscli`. The current package-page
generator only consumes entry values containing `:`, so formula executable
aliases are present in current data but not rendered on pages like
`/pkg/brew/awscli/`.

Needs new data for:

- complete multi-bin npm package mappings
- PyPI console scripts
- source path versus exposed target for Homebrew formulae
- daemon/service entrypoints
- global symlink/path behavior beyond generic install-root rules

### Metadata Section

Partly can do now.

Available now:

- cask homepage, URL, SHA-256, version, dependencies, popularity, last update
- npm homepage, executable, version, popularity, last update
- formula summary, aliases, popularity, and last update
- package-manager page URLs can be derived for Homebrew formulae/casks
- isotope release URLs and upstream repositories in isotope metadata

Needs new data for:

- formula homepage, latest version, license, and dependencies in the static DB
- repository URLs for most packages
- upstream docs URLs
- package-manager page URLs for npm/PyPI if we want explicit structured fields
- PyPI metadata at scale

### Related Packages

Mostly requires new data.

Some weak links can be derived now:

- dependencies for casks and selected install overlays
- aliases and old names for formulae
- isotope caveat references such as `aws-vault-binary`
- package families from versioned formula aliases
- approval-gated package lists

But the spec wants genuinely useful related software, alternatives, adjacent
tools, and dense internal navigation. That needs a generated or curated
relationship graph. Without it, links will look arbitrary.

### Cross-Ecosystem Links

Requires new data.

Current data has almost no equivalence mapping across ecosystems. We can infer
some obvious cases from names, aliases, and isotope `modifies`, but that is not
reliable enough for public pages.

A useful implementation needs an explicit cross-ecosystem identity table, for
example:

- `brew:awscli` -> `pip:awscli` if we decide that is truly equivalent
- `brew:node` -> `npm:npm` only as an adjacent relationship, not equivalent
- `brew:gh` -> isotope or approval-gate coverage

### Version / Freshness

Can do basic freshness now.

Available now:

- combined data generation timestamp
- package last-updated timestamps for formulae, casks, and npm records
- cask and npm versions
- isotope published/tag/version data

Needs new data for:

- formula latest versions in the static page dataset
- version lag checks
- abandoned-package warnings
- stale package policy thresholds

### Structured Technical Data

Can do now.

Current data is already structured enough for tables, lists, metadata blocks,
terminal snippets, and compact security notes.

### JSON-LD Structured Data

Partly can do now.

Current generated pages emit `SoftwareApplication`. The spec also asks for
`BreadcrumbList` and `TechArticle`, with possible `FAQPage` and `HowTo`.

`BreadcrumbList` and `TechArticle` can be added from current page structure.
`HowTo` can be generated for install commands. `FAQPage` should wait until we
have non-generic, package-specific questions or we risk SEO sludge.

### Sitemap Requirements

Partly can do now.

Current output has one `www/pkg/sitemap.xml`. Ecosystem-specific sitemaps and a
sitemap index are generator work, not a new data requirement.

## Requires New Generated Data

The highest-value missing datasets are:

1. Full Homebrew formula metadata snapshot
   - version
   - homepage
   - license
   - dependencies
   - bottle/files metadata if needed for trust notes
   - service blocks
   - install/post-install hooks

2. npm package metadata snapshot
   - package description
   - homepage/repository/license
   - all `bin` entrypoints
   - lifecycle scripts
   - dependencies or selected operational dependencies
   - latest version and publish time

3. PyPI package metadata snapshot
   - package description
   - homepage/project URLs
   - license
   - latest version and upload time
   - console scripts, likely from wheel metadata
   - dependencies when useful

4. Executable inventory expansion
   - normalize formula `entries` into package-page-ready executable lists
   - add source/target paths where available
   - collect npm multi-bin and PyPI console scripts

5. Install behavior and trust signals
   - lifecycle hooks
   - service/daemon installs
   - shell profile edits
   - remote binary downloads
   - privileged writes
   - package-manager signing/provenance claims

6. Relationship graph
   - related packages
   - alternatives
   - dependencies worth linking
   - same tool across ecosystems
   - isotope/approval/security adjacency

7. Page quality eligibility
   - index/noindex/skip decision per page
   - reason a page deserves to exist
   - minimum useful content score

## Generator Gaps, Not Data Gaps

These do not require new source data:

- render an explicit install section
- use existing Geiger data in security notes
- use formula executable entries whose provider value is currently unqualified
- render copy buttons and shell highlighting
- derive Homebrew package-manager page links
- add `BreadcrumbList`, `TechArticle`, and basic `HowTo` JSON-LD
- generate ecosystem-specific sitemaps
- improve title/H1/meta wording to match the spec
- noindex or skip pages below a quality threshold

## Practical Path

The best first pass does not need a large crawl:

1. Use current data plus Geiger to make Homebrew pages materially better.
2. Fix formula executable rendering from `../av.db/cache/automic-vault/db.json` `entries`.
3. Add explicit install commands and package-manager links.
4. Gate indexing: publish/index only pages with summary plus at least one of
   executable data, Geiger data, approval-gate data, isotope data, cask binary
   data, or npm executable/version data.
5. Generate full formula metadata next, because it unlocks version, homepage,
   license, dependencies, and stronger trust notes for the largest page set.
6. Add npm and PyPI registry snapshots after that.
7. Build the related/cross-ecosystem graph last; it is important, but low
   quality inferred links would actively weaken the package pages.
