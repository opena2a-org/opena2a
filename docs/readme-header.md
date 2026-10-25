# README header

Every public repository in the [opena2a-org](https://github.com/opena2a-org) organization opens its `README.md` with the same header block. A reader moving between repositories finds the name, the state, the family of tools and the way to the website and the community in the same place on every page. The [agent-identity-management README](https://github.com/opena2a-org/agent-identity-management#readme) is the model.

## The header block

Five parts, in this order. Each part is its own paragraph: a blank line separates every part from the next, because Markdown joins consecutive lines into one paragraph.

| Part | Form | Present |
|---|---|---|
| Title | `# <name>`: plain text and the only level-1 heading; never a link, an image or a badge | always |
| Badge row | One paragraph, one badge per source line, in the order status, version, downloads, CI, security, licence; at most one badge per class | where the repository has `STATUS.md` or `LICENSE` |
| Ecosystem line | One block quote of one line, the same in every repository | always |
| Link row | Links joined by ` · `: Website first, then Docs, Demos and one surface of the repository's own, then Discord last | always |
| Description | One paragraph that says what the repository is | always |

After the header comes the start block (the first command and its output), then the sections.

The licence is stated once, as the last badge, and never as text in the description. Nothing else above the first `##` heading repeats a header part: no second badge row, link row or ecosystem line, no horizontal rule and no logo.

## Required in every public repository

- Title.
- Status badge, first in the row, linking `STATUS.md`.
- Ecosystem line.
- Description.
- Licence badge, last in the row, linking `LICENSE`.
- Link row.

A badge never links a file that does not exist. A repository without `STATUS.md` carries no status badge until that file lands, and one without `LICENSE` carries no licence badge until it has a licence file.

## Present only where the thing exists

| Badge | Present when | How to check |
|---|---|---|
| Version | a package is published on npm or PyPI, or the extension is listed in a browser store | `npm view <package> version` prints a version |
| Downloads | a container image is published on Docker Hub | `https://hub.docker.com/r/opena2a/<image>` answers |
| CI | a workflow runs the repository's tests on pull requests or pushes to `main` | the workflow file exists and its badge renders `passing` or `failing` |
| Security | a workflow runs security checks on the repository: a security pipeline or a dependency audit | the workflow file exists and its badge renders `passing` or `failing` |
| Site link | the repository has a site of its own | the URL answers and is not the repository itself |

A documentation-only repository gets no CI badge it cannot earn. Every badge URL answers HTTP 200 and renders a real value; a badge that reads `unknown`, `not found`, `invalid`, `no status` or `retired` is fixed or removed before the header lands.

## Exact forms

Status, one colour per stage:

```markdown
[![Status: stable](https://img.shields.io/badge/status-stable-green)](STATUS.md)
[![Status: beta](https://img.shields.io/badge/status-beta-yellow)](STATUS.md)
[![Status: experimental](https://img.shields.io/badge/status-experimental-orange)](STATUS.md)
[![Status: reference-only](https://img.shields.io/badge/status-reference--only-blue)](STATUS.md)
```

Version, downloads, CI, security and licence, in that order:

```markdown
[![npm version](https://img.shields.io/npm/v/<package>.svg)](https://www.npmjs.com/package/<package>)
[![Docker](https://img.shields.io/docker/pulls/opena2a/<image>?label=docker%20pulls)](https://hub.docker.com/r/opena2a/<image>)
[![CI](https://github.com/opena2a-org/<repository>/actions/workflows/<workflow>.yml/badge.svg)](https://github.com/opena2a-org/<repository>/actions/workflows/<workflow>.yml)
[![Security](https://github.com/opena2a-org/<repository>/actions/workflows/<workflow>.yml/badge.svg)](https://github.com/opena2a-org/<repository>/actions/workflows/<workflow>.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
```

The version badge may link the package's releases page instead of its registry page. A repository whose own tests pin a badge's alt text or query string, such as `[![Tests](...badge.svg?branch=main)]`, keeps that form: it renders the same.

The ecosystem line, exactly:

```markdown
> **[OpenA2A](https://github.com/opena2a-org)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · [AIM](https://github.com/opena2a-org/agent-identity-management) · [Browser Guard](https://github.com/opena2a-org/ai-browserguard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)
```

In one of the six repositories it names, the line marks that repository's own entry as bold text without its link: `**CLI**` in this repository, `**AIM**` in agent-identity-management. Every other repository carries the line unchanged. A change to its members or their order is made in every repository at once, never in one README.

The link row, as this repository writes it:

```markdown
[Website](https://opena2a.org/cli) · [Docs](https://opena2a.org/docs) · [Demos](https://opena2a.org/demos) · [Discord](https://discord.gg/uRZa3KXgEn)
```

- Website is the repository's own site: its own domain, or its page on opena2a.org. Where it has neither, Website is https://opena2a.org. A domain that redirects to the repository itself is not a site.
- Docs, Demos and one surface of the repository's own, by its proper name (AIM Cloud, Privacy policy), appear only where they exist, each at most once and in that order.
- Discord is last, in every repository.
- No entry is an in-page anchor or a file in the repository; those belong in the body.

## The model

The agent-identity-management header:

```markdown
# OpenA2A AIM (Agent Identity Management)

[![Status: stable](https://img.shields.io/badge/status-stable-green)](STATUS.md)
[![Docker](https://img.shields.io/docker/pulls/opena2a/aim-server?label=docker%20pulls)](https://hub.docker.com/r/opena2a/aim-server)
[![CI](https://github.com/opena2a-org/agent-identity-management/actions/workflows/ci.yml/badge.svg)](https://github.com/opena2a-org/agent-identity-management/actions/workflows/ci.yml)
[![Security](https://github.com/opena2a-org/agent-identity-management/actions/workflows/security.yml/badge.svg)](https://github.com/opena2a-org/agent-identity-management/actions/workflows/security.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

> **[OpenA2A](https://github.com/opena2a-org)**: [CLI](https://github.com/opena2a-org/opena2a) · [HackMyAgent](https://github.com/opena2a-org/hackmyagent) · [Secretless](https://github.com/opena2a-org/secretless-ai) · **AIM** · [Browser Guard](https://github.com/opena2a-org/ai-browserguard) · [DVAA](https://github.com/opena2a-org/damn-vulnerable-ai-agent)

[Website](https://opena2a.org/agent-identity-management) · [AIM Cloud](https://aim.opena2a.org/get-started) · [Discord](https://discord.gg/uRZa3KXgEn)

Cryptographic identity, capability authorization, and audit trails for AI agents.
```

## The line budget

The first command and the first line of its output sit within 30 lines of the ecosystem line, or of line 1 in a README that has none. The header never pays for that budget: its parts are never joined, removed or reordered to fit, and the blank lines between them stay. A README over the budget moves content below its first section instead.

## Checking a header

```bash
awk '/^> \*\*\[OpenA2A/{print NR; exit}' README.md        # the ecosystem line's number
curl -s '<badge url>' | grep -o '<title>[^<]*</title>'   # a real value, not unknown or no status
```
