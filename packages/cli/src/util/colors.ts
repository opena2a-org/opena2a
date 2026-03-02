const enabled = process.env.NO_COLOR === undefined && process.stdout.isTTY;

function wrap(code: number, resetCode: number): (text: string) => string {
  if (!enabled) return (text: string) => text;
  return (text: string) => `\x1b[${code}m${text}\x1b[${resetCode}m`;
}

export const bold = wrap(1, 22);
export const dim = wrap(2, 22);
export const red = wrap(31, 39);
export const green = wrap(32, 39);
export const yellow = wrap(33, 39);
export const blue = wrap(34, 39);
export const cyan = wrap(36, 39);
export const gray = wrap(90, 39);
