# OpenA2A CLI

[![Status: stable](https://img.shields.io/badge/status-stable-green)](STATUS.md)
[![npm version](https://img.shields.io/npm/v/opena2a-cli.svg)](https://www.npmjs.com/package/opena2a-cli)
[![CI](https://github.com/opena2a-org/opena2a/actions/workflows/ci.yml/badge.svg)](https://github.com/opena2a-org/opena2a/actions/workflows/ci.yml)
[![Security](https://github.com/opena2a-org/opena2a/actions/workflows/security.yml/badge.svg)](https://github.com/opena2a-org/opena2a/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **[OpenA2A](https://github.com/opena2a-org)**: **CLI** · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/ai-browserguard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

[Website](https://opena2a.org/cli) · [Docs](https://opena2a.org/docs) · [Demos](https://opena2a.org/demos) · [Discord](https://discord.gg/uRZa3KXgEn)

`opena2a` is the command-line front door to the OpenA2A security tools. It assesses an AI agent project for hardcoded credentials and unsafe configuration, applies the fixes, and hands scanning, credential storage and package trust lookups to HackMyAgent, Secretless and ai-trust.

## Quick start

```bash
npx opena2a-cli init my-agent
```

What `npx opena2a-cli init my-agent` prints, trimmed ([full output](docs/captures/quick-start-init.txt)):

```
  Findings
  -----------------------------------------------
  CRITICAL  OpenAI Project Key
            OpenAI Project Key hardcoded in source. Anyone who can
            read this file can use it to access the associated
            account.
            src/agent.js:1
            Verify: sed -n '1p' src/agent.js
            Fix:    opena2a protect
  ...
  Security Score: 65 / 100  (project posture: credentials, config, environment)
```

`my-agent` is the path to your project; run the command from the directory that contains it. `init` reads the project and changes nothing. It needs Node.js 20.19 or later and no account, and it exits 1 while a critical finding is open, 0 otherwise.

Then apply the fixes and build the full report:

```bash
npx opena2a-cli protect my-agent
npx opena2a-cli review my-agent
```

`protect` moves each hardcoded credential out of the source files into Secretless, which stores it outside the project (a local vault or the OS keychain), and rewrites the source to read environment variables. `review` downloads the NanoMind model files on its first run and opens an HTML report in the browser; `--no-open` skips the browser.

## What you can do

Each line links to the section for that job.

- [Assess a project](docs/commands.md#assess-a-project): `opena2a init`
- [Check a package, MCP server, skill or repo](docs/commands.md#check-a-package-mcp-server-skill-or-repo): `opena2a check <target>`
- [Run a command with injected credentials](docs/commands.md#run-a-command-with-injected-credentials): `opena2a secrets run --only KEY -- <cmd>`
- [Look up a package's trust profile](docs/commands.md#look-up-a-packages-trust-profile): `opena2a trust <pkg>`
- [Give an agent an identity](docs/commands.md#give-an-agent-an-identity): `opena2a identity create --name X`
- [Run the OASB benchmark](docs/commands.md#run-the-oasb-benchmark): `opena2a benchmark`

## Built-in help

```bash
opena2a "~credentials"                 # search commands by keyword
opena2a "find leaked credentials"      # natural language to matched command
opena2a                                # interactive guided mode (no arguments)
```

Keep the quotes around the `~` form: zsh expands an unquoted `~word` before the CLI sees it. These lines use the installed command; with npx, write `npx opena2a-cli` in place of `opena2a`.

## Install

```bash
npm install -g opena2a-cli             # installs the opena2a command
brew install opena2a-org/tap/opena2a   # or with Homebrew
```

Requires Node.js 20.19 or later. To check where a release came from, see [Verifying OpenA2A npm packages](docs/verifying-npm-packages.md). To build from a clone, see [From source](CONTRIBUTING.md#from-source).

## Telemetry

Telemetry is on by default. `opena2a` sends usage events to the OpenA2A Registry at `api.oa2a.org`. Each event carries an install ID that identifies the machine, so the data is personal data. [opena2a.org/privacy](https://opena2a.org/privacy) explains how the ID is made.

An event holds the tool name and version, the command name (with an error code appended when the command fails), whether it succeeded, how long it took, the operating system platform, the Node.js major version and the install ID.

Turn it off for one run with `OPENA2A_TELEMETRY=off`, or for every run with `opena2a telemetry off`. `opena2a telemetry status` shows the current state, and `OPENA2A_TELEMETRY_DEBUG=print` prints each event to stderr. The policy is at [opena2a.org/telemetry](https://opena2a.org/telemetry).

## Documentation

In this repository:

- [Commands](docs/commands.md): every command by job, the optional authorization gate on `protect`, and AIM Cloud or a self-hosted server.
- [Use cases](docs/USE-CASES.md): walkthroughs for developers, security teams, MCP server authors and CI.
- [Post-incident review](docs/post-incident-review.md): reading the local audit log.
- [Recorded walkthrough of `review`](docs/images/review-demo.gif).
- [Contributing](CONTRIBUTING.md), [security policy](SECURITY.md) and [status](STATUS.md).

Elsewhere:

- [opena2a.org/docs](https://opena2a.org/docs), [demos](https://opena2a.org/demos), [research](https://research.opena2a.org) and [Discord](https://discord.gg/uRZa3KXgEn).
- Related tools: [HackMyAgent](https://github.com/opena2a-org/hackmyagent), [Secretless](https://github.com/opena2a-org/secretless-ai), [ai-trust](https://github.com/opena2a-org/ai-trust), [AIM](https://github.com/opena2a-org/agent-identity-management), [Browser Guard](https://github.com/opena2a-org/AI-BrowserGuard) and [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent).

## License

Apache-2.0. See [LICENSE](LICENSE).
