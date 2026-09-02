# sqlcmd

The sqlcmd Hardener installs the reviewed, Developer ID-signed sqlcmd Isotope
and moves supported basic-auth passwords from `~/.sqlcmd/sqlconfig` into
Automic Vault custody. The config retains only user, context, endpoint, and
`@av` marker metadata.

Password reads are bound to the verified sqlcmd Target, selected user profile,
endpoint, and complete command. Password creation and deletion use separate
approved mutation operations. Custom sqlconfig paths, unsupported
authentication, malformed markers, and missing Secret Values fail closed.

Legacy sqlcmd flags, `SQLCMD_PASSWORD`, `SQLCMDPASSWORD`, certificates, and
credentials supplied outside the default modern sqlconfig remain outside this
Hardener's coverage.
