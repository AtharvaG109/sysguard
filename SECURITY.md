# Security Policy

## Supported Scope

`sysguard` is currently a public prototype. Security fixes are most likely to be accepted for:
- Linux monitoring and policy-evaluation behavior
- outbound connect enforcement logic
- setup and run scripts

The macOS fallback mode is intended for development convenience, not strong security guarantees.

## Reporting a Vulnerability

Please do not open a public GitHub issue for suspected security vulnerabilities.

Instead, report privately with:
- a short description of the issue
- affected files or feature area
- reproduction steps
- impact assessment if known

If a private reporting channel is not yet configured, open a minimal GitHub issue asking for a private contact path without including exploit details.

## Response Expectations

As this is an individual-maintained prototype project:
- responses may take time
- fixes may land in small increments
- disclosures may be coordinated after a fix or mitigation is available

## Hardening Notes

Current limitations to keep in mind:
- kernel enforcement is intentionally narrow and currently focused on outbound IPv4 `connect`
- policy matching is not yet a full security boundary for every syscall type
- users should validate behavior in their own Linux environment before relying on it
