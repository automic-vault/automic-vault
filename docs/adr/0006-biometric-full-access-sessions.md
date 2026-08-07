# ADR 0006: Offer Biometric Full Access Sessions

- Status: Accepted
- Date: 2026-08-07

## Context

Users sometimes want an uninterrupted local automation window without changing every Authorization Gate or repeatedly responding to Approval prompts. Quitting the menu-bar helper does not provide that mode: protected Secrets become unavailable, Gate Clients fail, and reopening the app does not express a reviewed authority choice.

A literal “approve everything” switch would violate Automic Vault's fail-closed invariants. Unknown operations, unverifiable Launchers, untrusted Gate Clients or Targets, invalid requests, missing Secrets, and failed required Authorization Records cannot become allowed because a convenience mode is active. A durable global override would also outlive the user's immediate intent and obscure the per-gate policies that normally govern authority.

## Decision

Add an in-memory **Full Access Session**. While active, the policy resolver applies the Full Access Access Level at every Authorization Gate for Verified Launchers. The overlay includes recognized Elevated Secret Application and Secret Disclosure, but Unknown remains ineligible for automic authorization. All existing identity, integrity, request-validation, Secret-matching, and record-before-release requirements remain unchanged.

Only the signed macOS app UI can start a session. Starting requires `deviceOwnerAuthenticationWithBiometrics` through LocalAuthentication, with no password fallback. Authentication cancellation, failure, lockout, or unavailable biometry leaves normal policy active. Gate Clients, Launchers, CLI commands, URL handlers, XPC messages, environment variables, and persisted configuration receive no start mechanism.

A session lasts for at most one hour. It ends earlier when the macOS user session becomes inactive, the displays sleep, the app exits or updates, or the user selects **End Full Access Session**. Ending a session is always available without authentication because it narrows authority. The session is never persisted; app launch always starts under durable policy.

Make the exceptional state conspicuous:

- the menu-bar icon and menu use a warning treatment and show the remaining time;
- the main window shows a persistent warning banner with an End action;
- Settings explains exactly what Full Access includes and what still fails closed;
- Authorization History records allowed requests with `Full Access Session` as the policy reason.

The primary action is **Start Full Access Session…**, not a generic “disable approvals” toggle. The confirmation copy states that recognized operations from every Verified Launcher may use or disclose protected Secrets for up to one hour. Touch ID follows that explicit warning. Normal durable policy returns automatically when the session ends.

## Consequences

- A physically present user can authorize a bounded low-friction automation window without rewriting durable gate policy.
- Agents can open the app or attempt the action, but cannot satisfy local biometric authentication.
- Full Access Sessions broaden recognized authority intentionally, visibly, and temporarily; they never convert uncertainty into authority.
- Existing per-gate policy remains the source of truth before and after the session.
- Tests must cover biometric success and failure, expiry, lock and sleep termination, app-restart reset, verified versus unverifiable Launchers, every recognized Full Access classification, Unknown denial, Authorization History reasons, and the visible warning states.
