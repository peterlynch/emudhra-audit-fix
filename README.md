<!--

    Copyright (c) 2026-present Sonatype, Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.

-->

# eMudhra Dev Tools Audit

`emudhra-audit.sh` checks the developer tools installed on a machine against the
[eMudhra intermediate CA compromise](https://emudhra.we-have-a-problem.com/), and prints guidance for fixing anything
affected. By default it is **read-only**. With `--fix` it can also apply the fixes it knows about, one confirmed change at
a time, with backups and automatic rollback.

## Contents

- [Background](#background)
- [Quick start](#quick-start)
- [How it decides](#how-it-decides)
- [Scope](#scope)
- [Reading the output](#reading-the-output)
- [Options and exit codes](#options-and-exit-codes)
- [Remediation guidance](#remediation-guidance)
- [Applying fixes (`--fix`)](#applying-fixes---fix)
- [Requirements and portability](#requirements-and-portability)
- [Safety](#safety)
- [Limitations](#limitations)
- [Keeping it current](#keeping-it-current)
- [Development](#development)
- [The Fine Print](#the-fine-print)

## Background

Eight intermediate CA certificates issued by eMudhra had their private keys incorrectly generated, so anyone can recover
them from the certificates. An attacker holding one of those keys could impersonate any website or service to a client
that still trusts the chain. The fix is distrust, shipped through browsers, operating systems, language runtimes and
trust-store packages.

Which of your tools are protected depends on which trust store each one uses (the OS keychain, a bundled CA list, a JDK
`cacerts`, and so on), so one machine often has a mix of protected and affected tools. This script finds out which is which.

The authoritative source is <https://emudhra.we-have-a-problem.com/>. The fixed versions in this script were taken from
that page as of 2026-10-22; check the page for updates.

## Quick start

```bash
./emudhra-audit.sh              # full audit with live TLS probes and guidance
./emudhra-audit.sh --no-network # version checks only (no connections)
./emudhra-audit.sh --verbose    # also show the probe commands and raw TLS errors
./emudhra-audit.sh --fix --dry-run  # show exactly what a fix would do; change nothing
```

No installation is needed. The script is a single file; make it executable with `chmod +x emudhra-audit.sh` if required.

## How it decides

For each tool it finds, the script runs up to two checks.

1. **Live probe (authoritative).** The tool itself connects to two hosts that chain to the compromised intermediates, plus
   a control host (`https://github.com/`, chosen because it does not depend on either root the page says to distrust).
   - A TLS certificate error on the test hosts means the tool **rejects** the chain: protected.
   - A successful connection means the tool **trusts** the chain: affected.
   - If the control host also fails, the result is "inconclusive". This catches tools with no CA bundle, a proxy that
     intercepts TLS, or no network, so those failures are not mistaken for protection.
2. **Version check (explains why).** The tool's version is compared with the fixed releases listed on the page.

The probe wins when the two disagree. For example, Go on macOS can be older than the fixed release but still reject the
chain, because it uses the macOS system verifier, which already carries Apple's block. The script reports that as
protected, and lists the old version under "upgrade when convenient".

## Scope

| Tool | Live probe | Version check | Notes |
|---|---|---|---|
| curl | yes | no | The page lists no fixed curl version; it depends on the CA bundle in use. |
| git | yes (`git ls-remote`) | no | Uses the OS/curl bundle, so it can differ from other tools. Also reports `http.sslCAInfo` and `http.sslVerify=false`. |
| Go | yes | yes | Fixed in 1.26.10 and 1.27.3. |
| Python | yes (default store, `certifi` if installed, and `pip download`) | yes | Checks `certifi` >= 2026.10.19 and `pip` >= 26.2.2. Every interpreter found is checked. |
| Java (JDK/JRE) | yes, needs a `javac` somewhere on the machine | yes | Every install found is checked. Fixed in 8u511, 11.0.33, 17.0.21, 21.0.13, 25.0.5, 27.0.1. |
| Node.js | yes (and again with `--use-system-ca` when affected) | yes | Fixed in 22.23.4, 24.22.1, 26.12.1. |
| Deno | yes | yes | Fixed in 2.9.8. |
| Bun | yes | no | The page lists the fix as pending. |
| rustup | no | yes | Fixed in 1.29.2. |
| uv | no | yes | Fixed in 0.13.4. |
| pixi | no | yes | Fixed in 0.82.1. |
| mise | no | yes | Fixed in 2026.10.17. |
| Claude Code | no | yes | Fixed in 2.1.303. |
| Homebrew `ca-certificates` | yes (tests the bundle) | yes | Fixed in 2026-09-25_1. |
| System CA bundle files | yes (tests the file directly) | no | `/etc/ssl/cert.pem` and the usual Linux and BSD locations. |
| OS CA packages | no | yes | dpkg (Debian, Ubuntu), apk, pacman, and Fedora rpm. Other rpm distributions are reported without a verdict. |
| Electron apps (macOS) | no | yes | Reads the embedded Electron version from each app in `/Applications` and `~/Applications`. |

Installs are found through `PATH` and the common version managers and package managers: nvm, Volta, fnm, asdf, mise,
pyenv, SDKMAN, Homebrew, `/usr/lib/jvm`, `/Library/Java/JavaVirtualMachines` and similar locations.

### Not covered yet

- Rust crates inside your projects (`rustls-webpki` 0.103.16 and `webpki-roots` 1.0.10 are the fixed versions).
- Perl `Mozilla::CA`, Composer `ca-bundle`, Elixir `castore` and Erlang `certifi`.
- Containers, per-project virtualenvs and `node_modules`.
- Electron apps on Windows and Linux.
- Windows hosts (the script is a Bash script for Unix-like systems).

### Environment overrides

The script starts with a "CA-related environment" section listing variables that change which trust store a tool uses
(`SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `GIT_SSL_CAINFO`,
`NODE_EXTRA_CA_CERTS`, `NODE_USE_SYSTEM_CA`). It warns about settings that disable verification
(`GIT_SSL_NO_VERIFY`, `NODE_TLS_REJECT_UNAUTHORIZED=0`). The probes inherit your environment, so results describe how
each tool behaves in your shell, which may differ from a clean login or from CI.

## Reading the output

Each item gets a status line, then its path, version result and probe result.

| Status | Meaning |
|---|---|
| `AFFECTED` | The live probe connected to a host using the compromised chain. |
| `OK` | The live probe rejected the chain. |
| `LIKELY-AFFECTED` | No usable probe result, and the version is older than the fixed release. |
| `LIKELY-OK` | No usable probe result, and the version is at or above the fixed release. |
| `UNKNOWN` | Neither check gave an answer. |

At the end there is a summary count, followed by the remediation guidance.

## Options and exit codes

| Option | Effect |
|---|---|
| `--no-network` | Skip live probes and make no connections. Items that need a probe to resolve are reported as unknown. |
| `--no-guidance` | Do not print remediation guidance. |
| `--verbose` | Print each probe command and the raw TLS errors. |
| `--fix` | After the audit, offer to apply fixes, asking before each change. See [Applying fixes](#applying-fixes---fix). |
| `--dry-run` | With `--fix`: run every check and show every step, but change nothing. |
| `--yes` | With `--fix` or `--undo`: do not ask before each change (for unattended use). |
| `--only=KIND` | With `--fix`: apply one kind of fix only: `brew`, `sys`, `java` or `macpip`. |
| `--workaround-only` | With `--fix`: skip mention of the vendor package upgrade on Linux. |
| `--undo` | Restore the backups made by `--fix`. |
| `-h`, `--help` | Show usage. |

| Exit code | Meaning |
|---|---|
| `0` | Nothing affected or likely affected. |
| `1` | At least one item is affected or likely affected. |
| `2` | Usage error, or the script could not create its temporary directory. |

The exit codes make the script usable from CI or device management tooling.

## Remediation guidance

Guidance is printed after the summary in two groups:

- **Affected, fix these first.** Each item gets commands matched to how it was installed (for example `nvm install ...`,
  `sdk install java ...`, `brew upgrade ...`).
- **Protected today, but older than the fixed release.** Upgrade when convenient.

Where a tool reads the operating system's CA bundle, the guidance also includes the page's platform workaround
(macOS, Debian and Ubuntu, Alpine, Fedora and RHEL family, openSUSE, Arch, NixOS, FreeBSD, NetBSD). Only the block for the
current platform is printed, and only if an affected item needs it.

Prefer upgrading over the workaround. The workaround removes two widely used roots (`AAA Certificate Services` and
`emSign ECC Root CA - G3`) from the trust store, which can break legitimate sites that chain to them, and an OS update may
replace the edited file. Java and Electron apps use their own trust lists, so OS-level workarounds do not help them; they need an upgrade. Node.js
uses its own bundled list by default; the script tests `--use-system-ca` and says whether it helps on your machine.

If no fixed JDK build is available yet, the guidance for a Java install also prints a stop-gap: back up that JDK's
`cacerts` and delete the entries for the two roots. It is untested as a fix, makes Java reject sites chained to those
roots, and is undone by a JDK upgrade or by restoring the backup.

**Without `--fix` the script never runs any of this guidance.** It only prints it. Read each command before running it; the
trust-store commands need `sudo`.

After changing anything, run the script again to confirm.

## Applying fixes (`--fix`)

`--fix` changes the machine, so read this section before using it. **Prefer upgrading** the affected tool where a fixed
release exists; the fixes here distrust two roots, which has side effects.

### What it can fix

| Kind (`--only=`) | What it does | Needs sudo |
|---|---|---|
| `brew` | `brew update && brew upgrade ca-certificates` (an upgrade, not a trust-store edit). | no |
| `sys` | Removes the two roots from the system CA bundle: `/etc/ssl/cert.pem` on macOS; `ca-certificates.conf` plus `update-ca-certificates` on Debian, Ubuntu and Alpine; the p11-kit blocklist on Fedora, RHEL, SUSE and Arch. | yes |
| `java` | Deletes the two roots from a JDK's `cacerts`. A **stop-gap** for JDKs with no fixed build; a JDK upgrade restores them. | if the JDK is not yours |
| `macpip` | Appends the page's `PIP_CERT` line to Apple's Python `sitecustomize.py`. | yes |

The two roots are `AAA Certificate Services` (Comodo/Sectigo) and `emSign ECC Root CA - G3`. Nothing else is removed. The
script refuses to proceed if a change would remove more than expected.

### Safeguards

Each change follows the same sequence:

1. The new file or store is built on a **copy** first.
2. The copy is **tested**: it must reject the compromised chain, and it must still validate GitHub, Google, PyPI, Maven
   Central, npm and the Go module proxy. If a normal site would break, the change is refused.
3. You are **asked** (`--yes` skips this; with no terminal and no `--yes` nothing is changed).
4. The original is **backed up** next to itself as `<file>.pre-emudhra-<timestamp>`.
5. The change is installed, then the tool is **probed again**. If it does not reject the chain, the backup is restored
   automatically.

`--dry-run` stops before step 3 and prints the exact commands. `--undo` restores the newest backup for each store it
finds. Homebrew upgrades and p11-kit blocklist files are not covered by `--undo`; the notes printed after `--fix` say how
to reverse them.

### Side effects you should expect

- **Sites that chain to either root stop validating** in tools using the patched store. This is real: `example.com`
  currently chains to `AAA Certificate Services`. Check anything you depend on, such as internal or partner sites.
- **Updates can undo the change.** An OS update may replace `/etc/ssl/cert.pem`; a JDK upgrade restores the roots; an
  Xcode update replaces Apple's Python directory. Re-run the audit after updating.
- **Managed devices.** On a Mac enrolled in MDM the script warns you: IT may overwrite these edits or want to apply them
  centrally. The page does not recommend the Windows equivalent for enterprise-managed devices, and the same caution
  applies here.
- **It cannot patch what it cannot see**: Electron apps, bundled runtimes, containers and CI images need their own updates.

### What has been tested

| Path | Status |
|---|---|
| Root-stripping on a real macOS bundle (`tests/test_strip_roots.sh`) | Tested: exactly the two roots removed, all others unchanged by SHA-256. |
| Java `cacerts` fix, verify, idempotence, `--undo` and rollback | Tested end to end on a throwaway JDK copy. Restoring gave a byte-identical file. |
| `--dry-run` for `sys`, `java`, `brew` and `macpip` on macOS | Tested. |
| `--yes` validation, no-terminal behaviour, bad flags | Tested. |
| The macOS system-bundle edit itself (needs sudo), `brew` upgrade, `macpip` | **Not applied for real** in testing. Dry run only. |
| Debian, Ubuntu, Alpine, Fedora, RHEL, SUSE and Arch fixes | **Not tested.** The code follows the page's recipes but has not been run. |

Run the dry run first on any machine, and expect to read what it prints.

## Requirements and portability

- Bash 3.2 or later, which includes the stock macOS shell. The script avoids newer Bash features.
- Standard tools: `awk`, `sed`, `grep`, `readlink`, `mktemp`.
- Network access to `*.we-have-a-problem.com` and `github.com` for live probes. Use `--no-network` if that is not allowed.
- For the full set of probes, the relevant runtime must be installed. The script uses each tool's own runtime to test
  itself, so it does not need `jq` or any other extra dependency.
  - Java probes need a `javac` somewhere on the machine to compile the probe once. Without one, Java installs are
    checked by version only.
  - Testing CA bundle files and Homebrew's bundle uses a Python 3.8 or later interpreter found by the audit.

Tested on macOS (Apple silicon) with Bash 3.2. The Linux and BSD code paths (package checks, per-distribution guidance and
the `--fix` recipes) have **not** been exercised yet. The macOS workaround edits `/etc/ssl/cert.pem`; reports differ on whether macOS updates
refresh that file, so re-run the audit after updating rather than assuming.

## Safety

- Without `--fix` the script is read-only. It does not install, change or delete anything on the machine. See
  [Applying fixes](#applying-fixes---fix) for what `--fix` does.
- It writes small probe programs (Python, Go, Java, Node.js, Deno, Bun) into a private temporary directory and removes it
  on exit. Go probes run with `GOTOOLCHAIN=local` so Go does not download another toolchain, and Python runs in isolated
  mode (`-I`).
- Live probes make ordinary HTTPS requests to the two test hosts published on the reference page and to `github.com`.
  Nothing is sent beyond a normal `GET /`.
- Without `--fix`, guidance is text only.

## Limitations

- **A probe shows what the tool does now.** A tool can be protected only because the OS already blocks the chain. The
  version column shows whether the tool itself has the fix.
- **Version checks are approximate.** Fixed versions came from the reference page and may change as vendors ship fixes. A
  `NO FIX for this release line` result means the page lists no fixed release on that line, such as an Electron 37 app.
- **Embedded runtimes cannot be probed.** Electron apps and tools such as rustup, uv, pixi, mise and Claude Code are
  version-checked only.
- **Per-project dependencies are not scanned.**
- The script reports the machine it runs on; it does not scan remote hosts.

## Keeping it current

The fixed versions are hard-coded near the check for each tool (search for `check_*_version`, `vcmp` and
`audit_simple` in `emudhra-audit.sh`). When the page changes, for example when Bun or Erlang `certifi` ship a fix, update
those values and the `VERSION_OF_SCRIPT` number.

## Development

See [CONTRIBUTING.md](./CONTRIBUTING.md) for details.

## The Fine Print

Remember:

This project is part of the [Sonatype Nexus Community](https://github.com/sonatype-nexus-community) organization, which is not officially supported by Sonatype. Please review the latest pull requests, issues, and commits to understand this project's readiness for contribution and use.

* File suggestions and requests on this repo through GitHub Issues, so that the community can pitch in
* Use or contribute to this project according to your organization's policies and your own risk tolerance
* Don't file Sonatype support tickets related to this project— it won't reach the right people that way

Last but not least of all - have fun!
