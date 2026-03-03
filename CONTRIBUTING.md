# Contributing to OpenA2A

Thank you for your interest in contributing to OpenA2A. This guide covers
how to set up a development environment, run tests, and submit changes.

## Prerequisites

- Node.js >= 18
- npm >= 9
- Git

## Repository Structure

This is a monorepo managed by [Turborepo](https://turbo.build/):

```
packages/
  cli/      # opena2a-cli -- the main CLI tool (npm: opena2a-cli)
  shared/   # @opena2a/shared -- shared utilities and configuration
```

## Development Setup

```bash
# Clone the repository
git clone https://github.com/opena2a-org/opena2a.git
cd opena2a

# Install dependencies
npm install

# Build all packages
npx turbo build

# Run the CLI locally
node packages/cli/dist/index.js --help
```

## Running Tests

```bash
# Run all tests
npx turbo test

# Run tests for a specific package
cd packages/cli && npx vitest run

# Run tests in watch mode
cd packages/cli && npx vitest
```

## Making Changes

1. **Fork the repository** and create a branch from `main`:
   ```bash
   git checkout -b fix/short-description
   ```

2. **Make your changes.** Follow existing patterns in the codebase:
   - Commands go in `packages/cli/src/commands/`
   - Adapters go in `packages/cli/src/adapters/`
   - Shield modules go in `packages/cli/src/shield/`
   - Shared utilities go in `packages/shared/src/`

3. **Add tests** for new functionality. Tests live in `packages/cli/__tests__/`
   (organized by module: `commands/`, `shield/`, etc.) and use [Vitest](https://vitest.dev/).

4. **Build and test** before submitting:
   ```bash
   npx turbo build
   npx turbo test
   ```

5. **Submit a pull request** to `main` with a clear description of the
   change.

## Code Style

- TypeScript throughout (strict mode)
- No emojis in production code or user-facing output
- Console output uses `process.stdout.write()` and `process.stderr.write()`
  (not `console.log`)
- Colors use the shared palette in `packages/cli/src/util/colors.ts`
- camelCase for all JSON fields and TypeScript interfaces
- Prefer `node:` prefix for built-in modules (`import fs from 'node:fs'`)

## Adding a New Command

### Direct command (built into CLI)

1. Create `packages/cli/src/commands/yourcommand.ts`
2. Register it in `packages/cli/src/index.ts`
3. Add tests in `packages/cli/__tests__/commands/yourcommand.test.ts`

### Adapter command (wraps external tool)

1. Add an entry to `ADAPTER_REGISTRY` in `packages/cli/src/adapters/registry.ts`
2. Choose the adapter method: `import`, `spawn`, `docker`, or `python`
3. The adapter system handles fallback (npx/pipx) automatically

## Reporting Issues

- Search [existing issues](https://github.com/opena2a-org/opena2a/issues) first
- Include the output of `opena2a --version`
- Include the command you ran and the full output
- Include your Node.js version (`node --version`)

## License

By contributing, you agree that your contributions will be licensed under
the [Apache License 2.0](LICENSE).
