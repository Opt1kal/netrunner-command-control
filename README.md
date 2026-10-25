# NETRUNNER Command & Control

NETRUNNER C&C is an ongoing personal Python/Linux development and portfolio
project. It explores networking diagnostics, security-related workflows, modular
application design, and terminal user interfaces by coordinating existing tools.
It is a learning project, not a finished or production-hardened security product
or a supported software package.

## Current functionality

- **Ping:** five IPv4 ICMP probes, packet loss, and latency summaries.
- **DNS:** queries through `dig`, with explicit query names and record types.
  Root (`.`), trailing dots, service labels such as `_sip._tcp`, IDNA names, and
  generic record types such as `TYPE65` are supported inputs. An IP literal is a
  name query, not an automatic reverse lookup.
- **Route Trace:** IPv4 `traceroute`, with compact and verbose interactive views.
- **Port Scan:** RustScan discovery followed by Nmap service/version analysis of
  the discovered ports. Input accepts a single IPv4 address, IPv6 address, or
  hostname. A hostname must resolve to exactly one distinct address, which is
  passed to both tools; RustScan results must identify that same address.
- **Target Recon:** a consolidated DNS A-record query, Ping, and Route Trace
  report. These checks run independently and may resolve a hostname separately.
- Direct CLI commands and an interactive Networking menu, with structured result
  models and Rich terminal presentation.

## Requirements

- Linux. Other operating systems have not been validated.
- Python **3.14 or newer**; `.python-version` selects 3.14 for the default setup.
  The current development environment uses Python 3.14.4.
- `uv` for the setup procedure below. The project uses the `uv_build` build
  backend and declares Rich as its sole direct Python runtime dependency.
- External executables on `PATH`, installed separately:

| Capability | Executables |
| --- | --- |
| Ping | `ping` |
| DNS | `dig` |
| Route Trace | `traceroute` |
| Port Scan | `rustscan`, `nmap` |
| Target Recon | `dig`, `ping`, `traceroute` |

NETRUNNER does not bundle or install these system tools. Distribution package
names vary. RustScan 2.4.1 is the reference version for the known configuration
limitation below.

## Setup and launch

With `uv` and Python 3.14 already available, run from the repository root:

```bash
uv sync --locked --no-python-downloads
.venv/bin/nrc --help
.venv/bin/nrc
```

The sync command installs the project and its Python dependencies into `.venv`
using `uv.lock`. It does not install the external networking tools. The packaged
entry point is `nrc`; launching it without a subcommand opens the interactive
menu. In interactive input prompts, `0` returns to the menu; menu option `0`
returns or exits.

The existing installed entry point and an offline sync dry run have been checked.
A fresh installation on another machine has not been validated.

## CLI examples

These use documentation addresses and a reserved example domain. Replace them
with an appropriate authorized lab target; they are not expected to produce
successful live results as written.

```bash
.venv/bin/nrc ping 192.0.2.1
.venv/bin/nrc dns example.test AAAA
.venv/bin/nrc route 192.0.2.1
.venv/bin/nrc portscan 192.0.2.1
.venv/bin/nrc recon example.test
```

Omitting the target/query prompts for it. DNS defaults to record type `A`.
Use networking diagnostics and scans only against systems you own or are
authorized to test.

## Architecture

CLI and interactive input call reusable workflows or Sequences. Workflows ask a
tool adapter to build a `CommandRequest`, pass it to the subprocess runner, and
parse the `CommandResult` into a tool-specific result. Sequences compose
workflows; presentation renders their results.

```text
CLI / interactive menu
    → workflows / Sequences
    → tool adapters → subprocess runner
    → parsed results → Rich presentation
```

The project exercises Python packaging, dataclasses, subprocess integration,
output parsing, composition, terminal presentation, and mocked regression tests.

## Offline tests

From the repository root, using the prepared environment:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -B -m unittest discover -s tests -v
```

Tests use synthetic output and mocked execution/resolution. They do not require
live DNS queries, scans, or installed networking executables.

## Execution limits and known limitations

- **RustScan configuration isolation is deliberately deferred.** Inherited
  configuration in RustScan 2.4.1 may affect effective targets, selected ports,
  output formatting, or scripting. Input validation, numeric address pinning,
  and result-address checks do **not** guarantee RustScan's effective execution
  scope. Review the effective local RustScan configuration before using Port
  Scan. No discovery result proves that every possible port was checked.
- NETRUNNER applies conservative per-command wall-clock deadlines: Ping and DNS
  60 seconds each, Route Trace 10 minutes, RustScan 15 minutes, and Nmap 30 minutes.
  These are application limits, not the tools' internal packet/probe timeouts.
  Long legitimate operations can exceed them and are reported as failures.
  A failed RustScan prerequisite prevents the dependent Nmap step.
- Missing or inaccessible tools also produce failure results. Current result
  panels show a general failure status rather than the specific launch or
  timeout diagnostic retained by the runner.
- Deadlines cover subprocess execution, not hostname resolution performed before
  launch. Timeout handling stops and waits for the direct child; it does not
  guarantee termination of descendant processes. Comprehensive interactive
  cancellation and process-group supervision remain future work.
- Command output is captured in memory without a size limit. Streaming and
  resource limits are not implemented.
- Ping, Route Trace, and Target Recon currently use IPv4. Port Scan also accepts
  IPv6. Hostnames resolving to multiple distinct addresses are rejected by Port
  Scan; choose a specific authorized address.
- DNS answer parsing currently retains the final token of each answer record.
  Multi-token data such as TXT or MX records may therefore be incomplete in the
  displayed results. Arbitrary escaped DNS names and `dig` options/directives
  are not accepted as query input.
- Parsers depend on external tools' output formats. Offline regressions do not
  establish live interoperability across every tool version or environment.

## Licensing

No software license is currently included. Licensing remains an owner decision.
