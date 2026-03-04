/** Type declarations for optional dependency: hackmyagent */
declare module 'hackmyagent' {
  interface ShellFinding {
    severity: string;
    checkId: string;
    message: string;
  }
  export function checkShellEnvironment(): Promise<ShellFinding[]>;
  export function checkShellHistory(): Promise<ShellFinding[]>;
}
