/**
 * The server name for `opena2a mcp <audit|sign|verify>`, given as the
 * positional (`mcp sign filesystem`) or as `--server filesystem` (#344).
 *
 * Before `--server` was declared, `mcp sign --server X` failed with
 * "too many arguments for 'mcp'": the command allows unknown options, so
 * `--server` was skipped and `X` became a third positional.
 */
export function resolveMcpServerArg(
  positional: string | undefined,
  flag: string | undefined,
): { server: string | undefined } | { error: string } {
  if (flag !== undefined && positional !== undefined && flag !== positional) {
    return {
      error: `Two different servers given: '${positional}' and --server '${flag}'. Name one.`,
    };
  }
  return { server: flag ?? positional };
}
