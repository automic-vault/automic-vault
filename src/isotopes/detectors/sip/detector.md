# System Integrity Protection (SIP)

```sh
csrutil status
```

Disabled or reduced System Integrity Protection lets privileged code modify
parts of macOS that its default policy protects. This command reports that
system policy; it does not inspect a credential.

> ### What we check
>
> - `csrutil status` reports that System Integrity Protection is disabled or has
>   a custom configuration instead of being fully enabled.

## Mitigation

Boot into macOS Recovery, open Terminal, and run:

```sh
csrutil enable
```

Restart macOS, then verify that `csrutil status` reports `System Integrity
Protection status: enabled.` If SIP was disabled for legacy software or a
specialized development workflow, prefer updating or replacing that dependency
over leaving a machine-wide protection reduced.

---

## Rationale

System Integrity Protection is a mandatory access-control boundary enforced by
macOS. It limits what every process can do to protected parts of the operating
system, including processes running as `root`. With SIP fully enabled, ordinary
administrative privileges are not enough to overwrite protected system files or
modify Apple-provided apps; those operations are reserved for Apple-signed
processes with the required entitlements.

Disabling SIP therefore turns a local privilege escalation, stolen administrator
credential, malicious installer, or compromised privileged tool into a much more
durable compromise. Code that reaches `root` can tamper with operating-system
content that SIP would otherwise keep read-only, replace trusted components, and
make persistence harder to distinguish from the legitimate system. A custom SIP
configuration is also flagged because disabling even selected protections opens
part of this boundary, while `csrutil status` no longer attests that the complete
default policy is active.

SIP is defense in depth, not a substitute for software updates, least privilege,
Gatekeeper, or application sandboxing. Its value is that a failure in one of
those layers does not automatically grant permission to rewrite protected macOS
content. Because turning SIP off requires Recovery OS, finding it disabled also
usually indicates an intentional security-policy change that should be reviewed.

## References

- [About System Integrity Protection on your Mac](https://support.apple.com/102149)
- [Apple Platform Security: System Integrity Protection](https://support.apple.com/guide/security/system-integrity-protection-secb7ea06b49/web)
