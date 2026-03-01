export type AdapterType = 'import' | 'spawn' | 'docker' | 'python';

export interface AdapterOptions {
  verbose?: boolean;
  quiet?: boolean;
  ci?: boolean;
  format?: 'text' | 'json' | 'sarif';
  contribute?: boolean;
  args?: string[];
}

export interface AdapterResult {
  exitCode: number;
  stdout?: string;
  stderr?: string;
  findings?: Finding[];
}

export interface Finding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  file?: string;
  line?: number;
  remediation?: string;
}
