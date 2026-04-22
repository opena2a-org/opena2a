export type RegistryErrorCode =
  | "not_found"
  | "unauthorized"
  | "forbidden"
  | "rate_limited"
  | "bad_request"
  | "server_error"
  | "network"
  | "timeout"
  | "invalid_response";

export class PackageNotFoundError extends Error {
  readonly code: "not_found" = "not_found";
  readonly packageName: string;

  constructor(name: string) {
    super(`Package "${name}" not found in the OpenA2A Registry.`);
    this.name = "PackageNotFoundError";
    this.packageName = name;
  }
}

export class RegistryApiError extends Error {
  readonly code: RegistryErrorCode;
  readonly statusCode?: number;
  readonly body?: string;

  constructor(
    message: string,
    code: RegistryErrorCode,
    statusCode?: number,
    body?: string,
  ) {
    super(message);
    this.name = "RegistryApiError";
    this.code = code;
    this.statusCode = statusCode;
    this.body = body;
  }
}

export function classifyHttpStatus(status: number): RegistryErrorCode {
  if (status === 400) return "bad_request";
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not_found";
  if (status === 429) return "rate_limited";
  if (status >= 500) return "server_error";
  return "server_error";
}
