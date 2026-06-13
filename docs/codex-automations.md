# Codex Automations

Use native Codex/ChatGPT scheduled automations for the publishing cadence.
Do not use `launchd` for this repo-owned cadence.

Automations were split with package database ownership:

- `~/src/av.db` owns database refresh, package data generation, `/db.json`
  cache exports, and `pkg.sqlite` generation.
- `~/src/av.www` owns the static website deploy surface plus the Atlas
  `av-web` package-origin deploy.
- `~/src/automic-vault` does not own these automation dispatchers.

## Hourly Database Publish

Schedule: every hour at minute 0.

Prompt:

```text
In /Users/mxcl/src/av.db, run the hourly Automic Vault database publish.

Use this command:
/Users/mxcl/src/av.db/scripts/automation-runner.sh db

After it finishes, inspect cache/automation/db.status.json and the tail of cache/automation/db.log. If it failed or timed out, diagnose the failure, make the smallest safe fix in the repo, run the relevant tests, commit at a sensible interval, and then rerun /Users/mxcl/src/av.db/scripts/automation-runner.sh db once.

Preserve public /db.json schema compatibility. Do not bump the public database schema for additive fields, and keep volatile timestamps, versions, generated graph data, final JSON, and SQLite artifacts in cache rather than committed source files.
```

## Daily Package-Origin Publish

Schedule: daily at 03:15 local time.

Prompt:

```text
In /Users/mxcl/src/av.www, run the daily Automic Vault package-origin publish.

Use this command:
/Users/mxcl/src/av.www/scripts/automation-runner.sh pkg-origin

After it finishes, inspect cache/automation/pkg-origin.status.json and the tail of cache/automation/pkg-origin.log. If it failed or timed out, diagnose the failure, make the smallest safe fix in the relevant repo, run the relevant tests, commit at a sensible interval, and then rerun /Users/mxcl/src/av.www/scripts/automation-runner.sh pkg-origin once.

Remember that package catalog routes are served by av-web from /Users/mxcl/src/av.db/cache/pkg.sqlite locally and /var/lib/automic-vault-web/pkg.sqlite on Atlas. Database generation fixes usually belong in /Users/mxcl/src/av.db; av-web/deploy fixes usually belong in /Users/mxcl/src/av.www.
```

## Weekly npm Full Scan

Schedule: weekly, early morning local time.

Prompt:

```text
In /Users/mxcl/src/av.db, run the Automic Vault npm full package scan.

Use this command:
/Users/mxcl/src/av.db/scripts/automation-runner.sh npm-full-scan

After it finishes, inspect cache/automation/npm-full-scan.status.json and the tail of cache/automation/npm-full-scan.log. If it failed or timed out, diagnose the failure, make the smallest safe fix in /Users/mxcl/src/av.db, run the relevant tests, commit at a sensible interval, and then rerun /Users/mxcl/src/av.db/scripts/automation-runner.sh npm-full-scan once.
```

## Health Check

Schedule: every day at 08:00 local time.

Prompt:

```text
Check the Automic Vault Codex automation status across the split repos.

Use these commands:
/Users/mxcl/src/av.db/scripts/codex-automation-status.sh
/Users/mxcl/src/av.www/scripts/codex-automation-status.sh

If any job is failed, timed out, stale, or currently running far beyond its expected cadence, inspect the relevant log under cache/automation/, diagnose the issue, make the smallest safe fix in the owning repo, run the relevant tests, commit at a sensible interval, and rerun only the affected automation-runner job once.
```
