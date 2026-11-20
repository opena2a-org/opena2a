# Recipe fixtures

`.github/workflows/recipe.yml` runs the Quick Start of `docs/use-cases/ci-cd.md` against each directory here, with the CLI built from the commit under test. The recipe refuses a project when its review score is below 50 (step 2, `review`, exits 1) or its governance score is below 60 (step 3, the gate, exits 1). Each directory exists to be refused by exactly one of those, or by neither.

| Directory | Step 2 (`review`) | Step 3 (gate) | What puts it there |
|---|---|---|---|
| `agent-review-below-50/` | exit 1, score below 50 | not run | `.mcp.json` declares `shell-runner`, an MCP server with shell access. `detect` rates it critical; `review` reports it as the `shadow-ai` finding `mcp-server`, and the Project Governance floor holds the score below 50. Governance stays at 60 or more. |
| `agent-governance-below-60/` | exit 0, score 50 or more | exit 1, governance below 60 | `ai.config.json`, `ai.config.yml` and `langchain.config.js` each grant broad permissions, and `detect` rates each high. Together they take governance below 60. None is critical, so the review score is not floored. |
| `agent-benign/` | exit 0, score 50 or more | exit 0, governance 60 or more | A `SOUL.md`, one AI configuration that asks for approval (rated low), and no MCP server. |

`agent-review-below-50/` is `agent-benign/` with `.mcp.json` added.

The files are configuration only: nothing here runs, and nothing here is a credential. They are scanned, not executed.

`packages/cli/__tests__/recipe/recipe-fixtures.test.ts` runs the built CLI on each directory and names the findings above. It also removes the planted files from a copy and checks that the copy clears the threshold, so a scoring change that moves a directory to the other side of its threshold fails `npm test` before it can make the workflow's control pass for another reason.

**Verify locally** (from the repository root, after `npm ci && npm run build`):

```bash
node packages/cli/dist/index.js detect test/fixtures/recipe/agent-governance-below-60 --format json --ci > /tmp/detect.json
jq '.summary.governanceScore' /tmp/detect.json
node packages/cli/dist/index.js review test/fixtures/recipe/agent-review-below-50 --format json --ci --skip-hma > /tmp/review.json
echo "review exit: $?"
jq '.compositeScore' /tmp/review.json
```

`detect` also counts AI tools running on the machine it runs on, so on a workstation the governance score can be lower than on the CI runner.
