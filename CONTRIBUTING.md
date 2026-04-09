# Contributing to Sysguard

Thanks for taking a look at `sysguard`.

## Scope

The project is currently:
- Linux-first
- centered on Rust + Aya eBPF workflows
- honest about partial enforcement support

Please prefer small, reviewable changes over broad refactors.

## Local Development

Linux development:
```bash
./scripts/linux-vm-setup.sh
./scripts/build-release.sh
sudo ./scripts/run.sh --uid 1000
```

macOS development:
```bash
./scripts/macos-setup.sh
./scripts/build-release.sh
./scripts/run.sh
```

## Validation

Before opening a PR, run what applies:
```bash
cargo test -p sysguard --bin sysguard
bash -n scripts/linux-vm-setup.sh
bash -n scripts/build-release.sh
bash -n scripts/run.sh
```

On Linux, also try:
```bash
./scripts/linux-smoke-test.sh
./scripts/linux-enforce-test.sh
```

## Style

- Keep changes focused.
- Prefer ASCII unless the file already uses Unicode.
- Preserve the existing Linux-first design.
- Document limits clearly when adding new features.

## Pull Requests

Good PRs usually include:
- a short problem statement
- the change made
- how it was validated
- any limitations or follow-up work
