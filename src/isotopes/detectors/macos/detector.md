# macOS Detector

> ### What we check
>
> - The launchd `PATH` inherited by GUI applications places a user-writable
>   directory before protected system directories.
>
> The scan report also prints the GUI `PATH` as informational context, including
> when its ordering is safe. An unset launchd `PATH` is printed as `<unset>` and
> is not reported as insecure because system command lookup then uses the
> platform default rather than an empty path entry.
>
> #### Sensitive Files
>
> - Directories listed in the launchd `PATH`

## Mitigation

Move protected system directories before user-writable directories in the
launchd `PATH`, remove empty and relative entries, then log out and back in.
Review LaunchAgents and other software that modifies the launchd environment
before changing it; an unexpected entry may indicate persistence.

Automic Vault does not modify the GUI environment automatically. Its source can
be a LaunchAgent, a system policy, or software with different lifecycle and
ownership requirements, so a blind rewrite could conceal persistence or break
applications.
