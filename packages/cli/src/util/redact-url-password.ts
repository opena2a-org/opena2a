/** Replace the password of every URL with user information: the part after
 *  the user name's colon (the name may be empty, as in `redis://:…@host`), up
 *  to the last `@` before whitespace. A scanner's error text need not be a
 *  valid URL, so the password may hold `/` or `@`, and it may be any length.
 *  Each run of text without whitespace is read once, front to back, so the time
 *  grows with the length of the text rather than its square. */
export function redactUrlPasswords(text: string, replacement: string): string {
  return text.replace(/\S+/g, (run) => {
    const lastAt = run.lastIndexOf('@');
    for (let sep = run.indexOf('://'); sep !== -1 && sep < lastAt; sep = run.indexOf('://', sep + 3)) {
      if (sep === 0 || !/[a-z0-9+.-]/i.test(run[sep - 1])) continue;
      let end = sep + 3;
      while (end < run.length && !'/@:'.includes(run[end])) end++;
      if (run[end] !== ':' || end + 1 >= lastAt) continue;
      return `${run.slice(0, end + 1)}${replacement}${run.slice(lastAt)}`;
    }
    return run;
  });
}
