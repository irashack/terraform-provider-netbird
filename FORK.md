# irashack/terraform-provider-netbird

A maintenance fork of [netbirdio/terraform-provider-netbird](https://github.com/netbirdio/terraform-provider-netbird)
for one self-hosted NetBird account. It exists because upstream 0.0.10 resets live
settings it does not model on every update, including local MFA, the IPv6 overlay,
and a private reverse-proxy service's access groups (turning it public). Each fix
below is written as its own upstream-shaped change, and any of them can be proposed
as a pull request.

Branch: `main-maintenance`. Source address: `registry.terraform.io/irashack/netbird`,
installed from a filesystem mirror. Nothing is published to a registry and releases
are unsigned; verify the `SHA256SUMS` digest recorded in the release notes and the
build attestations (`gh attestation verify`).

## Versions

Fork releases on the 0.0.x line are numbered from `0.0.1001`, so they can never share
a number with an upstream release. Releases are a manual dispatch of the `Release`
workflow for an existing tag on `main-maintenance`, which builds a draft.

## Divergence from upstream

| Change | Upstream status |
|---|---|
| IPv6 overlay settings on account settings and peer | Upstream PR #215 (open), picked unchanged |
| Account settings: carry every unmodelled setting forward on update | Not upstream |
| Account settings: `local_mfa_enabled` | Not upstream |
| Policies and routes: keep unconfigured fields on update instead of resetting them; `[]`/`{}` clears | Not upstream |
| Posture check: an unset description stays null | Not upstream |
| Reverse-proxy services: `private`, `access_groups`, cluster targets, `direct_upstream`, `crowdsec_mode` | Not upstream |
| Reverse-proxy services: keep unconfigured target host/path/options, access restrictions and mode; show out-of-band target drift | Not upstream |
| Release: manual, draft-only, unsigned, attested | Fork-only, never proposed |

Fork commits carry a `Co-Authored-By` trailer. Upstream's AGENTS.md forbids that
trailer, so an upstream pull request is rebuilt as a clean single-purpose branch.
