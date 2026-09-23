# 0051: Embedded Touch ID Approval

Status: accepted

## Context

Touch ID Approval currently requires clicking an Approval action before macOS
presents a separate authentication prompt. Apple provides `LAAuthenticationView`
for biometric evaluation within the window that explains the request.

## Decision

When Touch ID Approval is separately enabled, use Apple's embedded view by
default. Start a fresh biometric-only evaluation after displaying the immutable
request. Its result means Approve Once only. The native mini-size indicator sits
inside the approval status pill, which accepts neither clicks nor keyboard
activation. Broader actions live in a separate menu and cancel that attempt
before evaluating their explicitly selected scope in the system prompt.

Keep the existing no-reuse, no-password, no-companion policy, active-session and
awake-display requirements, exact-request binding, first-result-wins handling,
and record-before-release checks. Invalidate embedded authentication on window
teardown and reject callbacks from canceled or replaced attempts.

Offer “Use Touch ID directly in the Approval window” in Touch ID Approval
settings. Store this independent preference in the Data Protection Keychain,
including an explicit false value. An absent value defaults on; unreadable or
malformed values select the click-first flow. Changing it cancels the current
Approval. It cannot enroll or enable Touch ID Approval.

## Consequences

The user can approve the displayed request with a deliberate touch without a
prior click. Touching the sensor while an unexpected request is displayed can
approve that request; the surrounding UI identifies the exact request and the
Approve Once action. Users who want the additional click can disable embedded
presentation. This changes the interaction sequence, not the biometric or
request-verification boundary. Same-user preference-file edits cannot reverse
the opt-out. Hardware validation must cover a non-activating panel, failed and
canceled authentication, denial, a phone response winning, and broader actions.
