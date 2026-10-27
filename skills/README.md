# Agent Skills

Instructions that teach coding agents how to work with Automic Vault. Each
directory is an [Agent Skill](https://agentskills.io): a `SKILL.md` with a
name and a description that tells the agent when to use it.

- [`blessed-script`](blessed-script/SKILL.md): write a Blessed Script and ask
  the user to bless it.
- [`reentrant-blessed-script`](reentrant-blessed-script/SKILL.md): write or
  follow a reentrant Blessed Script that pauses for agent input.

To install one, copy its directory into your agent's skills directory, for
example `~/.claude/skills/` for Claude Code.

A skill grants no authority. The agent still needs the user to review every
Blessing and answer every Approval.
