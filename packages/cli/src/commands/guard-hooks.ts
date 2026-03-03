/**
 * ConfigGuard pre-commit hook integration.
 *
 * Installs/uninstalls a git pre-commit hook that runs `opena2a guard verify`
 * before each commit, preventing commits when config files have been tampered.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { bold, green, yellow, red, dim } from '../util/colors.js';

// --- Types ---

export interface InstallResult {
  installed: boolean;
  path: string;
  appended: boolean;
  message: string;
}

// --- Constants ---

const HOOK_MARKER = '# opena2a-guard pre-commit hook';
const HOOK_END_MARKER = '# end opena2a-guard pre-commit hook';

// --- Hook script ---

function getHookScript(): string {
  return [
    HOOK_MARKER,
    '# Verify config file integrity before committing.',
    '# Set SKIP_GUARD_VERIFY=1 to bypass in emergencies.',
    'if [ "$SKIP_GUARD_VERIFY" = "1" ]; then',
    '  echo "[guard] SKIP_GUARD_VERIFY is set -- skipping config integrity check."',
    'else',
    '  if [ -f ".opena2a/guard/signatures.json" ]; then',
    '    npx opena2a guard verify --ci --format text',
    '    GUARD_EXIT=$?',
    '    if [ $GUARD_EXIT -ne 0 ]; then',
    '      echo ""',
    '      echo "[guard] Config integrity check FAILED. Commit blocked."',
    '      echo "[guard] Run: opena2a guard sign   to re-sign after intentional changes."',
    '      echo "[guard] Set SKIP_GUARD_VERIFY=1 to bypass in emergencies."',
    '      exit 1',
    '    fi',
    '  fi',
    'fi',
    HOOK_END_MARKER,
    '',
  ].join('\n');
}

// --- Install ---

function installPreCommitHook(targetDir: string): InstallResult {
  const gitDir = path.join(targetDir, '.git');
  if (!fs.existsSync(gitDir) || !fs.statSync(gitDir).isDirectory()) {
    return {
      installed: false,
      path: '',
      appended: false,
      message: 'No .git directory found. Is this a git repository?',
    };
  }

  const hooksDir = path.join(gitDir, 'hooks');
  fs.mkdirSync(hooksDir, { recursive: true });

  const hookPath = path.join(hooksDir, 'pre-commit');
  const hookScript = getHookScript();
  let appended = false;

  if (fs.existsSync(hookPath)) {
    const existing = fs.readFileSync(hookPath, 'utf-8');

    // Already installed -- replace with latest version
    if (existing.includes(HOOK_MARKER)) {
      const before = existing.slice(0, existing.indexOf(HOOK_MARKER));
      const afterMarker = existing.indexOf(HOOK_END_MARKER);
      const after = afterMarker >= 0
        ? existing.slice(afterMarker + HOOK_END_MARKER.length).replace(/^\n/, '')
        : '';
      const updated = before + hookScript + after;
      fs.writeFileSync(hookPath, updated, 'utf-8');
      fs.chmodSync(hookPath, 0o755);
      return {
        installed: true,
        path: hookPath,
        appended: false,
        message: 'Pre-commit hook updated.',
      };
    }

    // Foreign hook exists -- append ours
    const separator = existing.endsWith('\n') ? '\n' : '\n\n';
    fs.writeFileSync(hookPath, existing + separator + hookScript, 'utf-8');
    appended = true;
  } else {
    fs.writeFileSync(hookPath, '#!/bin/bash\n\n' + hookScript, 'utf-8');
  }

  fs.chmodSync(hookPath, 0o755);

  return {
    installed: true,
    path: hookPath,
    appended,
    message: appended
      ? 'Pre-commit hook appended to existing hook.'
      : 'Pre-commit hook installed.',
  };
}

// --- Uninstall ---

function uninstallPreCommitHook(targetDir: string): boolean {
  const hookPath = path.join(targetDir, '.git', 'hooks', 'pre-commit');
  if (!fs.existsSync(hookPath)) return false;

  const content = fs.readFileSync(hookPath, 'utf-8');
  if (!content.includes(HOOK_MARKER)) return false;

  const before = content.slice(0, content.indexOf(HOOK_MARKER));
  const afterMarker = content.indexOf(HOOK_END_MARKER);
  const after = afterMarker >= 0
    ? content.slice(afterMarker + HOOK_END_MARKER.length).replace(/^\n/, '')
    : '';

  const remaining = (before + after).trim();

  if (!remaining || remaining === '#!/bin/bash') {
    // Nothing left -- remove the file entirely
    fs.unlinkSync(hookPath);
  } else {
    fs.writeFileSync(hookPath, remaining + '\n', 'utf-8');
  }

  return true;
}

// --- Status ---

function isHookInstalled(targetDir: string): boolean {
  const hookPath = path.join(targetDir, '.git', 'hooks', 'pre-commit');
  if (!fs.existsSync(hookPath)) return false;
  const content = fs.readFileSync(hookPath, 'utf-8');
  return content.includes(HOOK_MARKER);
}

// --- CLI handler ---

export async function guardHook(
  action: string,
  targetDir: string,
): Promise<number> {
  switch (action) {
    case 'install': {
      const result = installPreCommitHook(targetDir);
      if (!result.installed) {
        process.stderr.write(red(result.message) + '\n');
        return 1;
      }
      process.stdout.write(green(result.message) + '\n');
      process.stdout.write(dim(`  ${result.path}`) + '\n');
      return 0;
    }

    case 'uninstall': {
      const removed = uninstallPreCommitHook(targetDir);
      if (removed) {
        process.stdout.write(green('Pre-commit hook removed.') + '\n');
      } else {
        process.stdout.write(yellow('No ConfigGuard hook found to remove.') + '\n');
      }
      return 0;
    }

    case 'status': {
      const installed = isHookInstalled(targetDir);
      if (installed) {
        process.stdout.write(bold('ConfigGuard pre-commit hook: ') + green('installed') + '\n');
      } else {
        process.stdout.write(bold('ConfigGuard pre-commit hook: ') + dim('not installed') + '\n');
      }
      return 0;
    }

    default:
      process.stderr.write(red(`Unknown hook action: ${action}`) + '\n');
      process.stderr.write('Usage: opena2a guard hook <install|uninstall|status>\n');
      return 1;
  }
}

// --- Testable internals ---

export const _internals = {
  HOOK_MARKER,
  HOOK_END_MARKER,
  getHookScript,
  installPreCommitHook,
  uninstallPreCommitHook,
  isHookInstalled,
};
