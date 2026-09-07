# ADR 0041: Permit an opt-in collapsible Temporary Access Grant strip

Status: accepted

## Context

The persistent Temporary Access Grant strip keeps temporary Write Access
conspicuous, but it can cover unrelated content for the grant's full lifetime.
Hiding it completely would remove a deliberate safety signal while authority
remains active. Its menu-bar item already turns orange and exposes every active
grant and action.

## Decision

Keep the complete strip as the default. Add an off-by-default setting that
collapses it after five seconds into a visible warning tab at the nearest
horizontal screen edge. Selecting the tab or the menu action restores the
complete strip and restarts the delay. Creating a new grant also restores it.

Collapsing changes presentation only. It does not suspend, extend, end, or alter
a grant. The status-item shield remains orange, the menu continues to list every
active grant, and End remains immediately available. The warning tab uses a
standard button with a full-size hit target and does not depend on color alone.

## Consequences

Users who enable the setting reclaim most of the covered screen area without
making temporary Write Access invisible. The complete grant details are no
longer continuously readable while collapsed, so the behavior remains an
explicit opt-in rather than the default. The edge tab also avoids depending on
the status item's horizontal position after the initial five-second display.
