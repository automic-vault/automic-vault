# macOS

```sh
launchctl getenv PATH
```

This shows the command-search path inherited by GUI applications. A writable
directory before protected system directories can supply a replacement command
that an app runs under your account. The command prints configuration, not
credentials.

> ### What we check
>
> - The launchd `PATH` inherited by GUI applications places a user-writable
>   directory before protected system directories.
> - A readable process running as your user has the same unsafe ordering in
>   its environment, including commands launched from a terminal shell.
>
> The scan report also prints the GUI `PATH` as informational context, including
> when its ordering is safe. An unset launchd `PATH` is printed as `<unset>` and
> is not reported as insecure because system command lookup then uses the
> platform default rather than an empty path entry.
>
> #### Sensitive Files
>
> - Directories listed in the launchd `PATH`
> - Directories listed in observed user-process `PATH` values

The GUI scanner does not inherit your terminal's `PATH`. To cover that gap,
the macOS detector passively reads process environments and retains PATH values,
PIDs, and executable paths for this Scan. It wipes the temporary environment
buffers and never executes shell startup files. Findings identify the risky
directory and up to 16 observed processes, with a count of additional processes,
without including process arguments or other environment values. This is
scan-time attribution, not Verified Launcher identity. Refresh before acting on
a PID because the process may have exited and its PID may have been reused.

This is a bounded snapshot of up to 16,384 processes with at most 1 MiB of
argument and environment data per process and 1 MiB of retained PATH and
executable-path bytes across the Scan. Exited processes, unreadable
environments, and oversized snapshots are outside its coverage. macOS may
expose the environment from process launch rather than subsequent changes;
commands launched after a shell changes PATH can supply that updated evidence.
An absent Finding does not establish that every shell's PATH is safe.

The PATH check recognizes command directories inside vendor-signed apps under
`/Applications` when the app executable and every file in that directory pass
targeted signature validation. This accounts for macOS App Management protection
despite Unix write permissions. It does not check existing App Management grants
or certify unrelated bundle resources. Added or modified files, symlinks,
unsupported layouts, and validation errors retain the warning. Checks are shared
within this detector pass and refreshed on the next Scan. See
[ADR 0078](../../../../../docs/adr/0078-sealed-application-path-directories.md).

## Mitigation

Review the shell configuration, LaunchAgents, or application settings that
supplied the reported PATH. Move protected system directories before
user-writable directories and remove empty, relative, and unexpected entries,
then restart affected shells and applications. If version-manager ordering is
intentional, use absolute paths for security-sensitive commands; this does not
make the PATH safe. An unexpected entry may indicate persistence.

Automic Vault does not modify the GUI environment automatically. Its source can
be a LaunchAgent, a system policy, or software with different lifecycle and
ownership requirements, so a blind rewrite could conceal persistence or break
applications.
