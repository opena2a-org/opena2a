/** Type declarations for optional dependency: secretless-ai */
declare module 'secretless-ai' {
  interface InitResult {
    toolsConfigured?: string[];
    secretsFound?: number;
    filesCreated?: string[];
  }
  export function init(targetDir: string): InitResult;
}
