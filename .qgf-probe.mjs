// Scratch probe (not committed): fetch JSON over HTTPS through HTTP_PROXY via CONNECT.
import http from 'node:http';
import tls from 'node:tls';

export function fetchViaProxy(host, pathName, headers = {}) {
  const proxy = process.env.HTTPS_PROXY || process.env.HTTP_PROXY;
  return new Promise((resolve, reject) => {
    if (!proxy) return reject(new Error('no proxy set'));
    const u = new URL(proxy);
    const req = http.request({ host: u.hostname, port: u.port, method: 'CONNECT', path: `${host}:443` });
    req.on('connect', (res, socket) => {
      if (res.statusCode !== 200) return reject(new Error(`CONNECT ${res.statusCode}`));
      const t = tls.connect({ socket, servername: host }, () => {
        const lines = [
          `GET ${pathName} HTTP/1.1`,
          `Host: ${host}`,
          'User-Agent: qgf-probe',
          'Accept: application/vnd.github+json, application/json',
          'Connection: close',
          ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
          '',
          '',
        ];
        t.write(lines.join('\r\n'));
      });
      let buf = '';
      t.on('data', (d) => (buf += d));
      t.on('end', () => {
        const idx = buf.indexOf('\r\n\r\n');
        const head = buf.slice(0, idx);
        let body = buf.slice(idx + 4);
        const status = Number(head.split(' ')[1]);
        if (/transfer-encoding:\s*chunked/i.test(head)) {
          // de-chunk
          let out = '';
          let rest = body;
          while (rest.length > 0) {
            const nl = rest.indexOf('\r\n');
            if (nl === -1) break;
            const size = parseInt(rest.slice(0, nl), 16);
            if (!size) break;
            out += rest.slice(nl + 2, nl + 2 + size);
            rest = rest.slice(nl + 2 + size + 2);
          }
          body = out;
        }
        resolve({ status, body });
      });
      t.on('error', reject);
    });
    req.on('error', reject);
    req.end();
  });
}

if (process.argv[2]) {
  const { status, body } = await fetchViaProxy(process.argv[2], process.argv[3] ?? '/');
  console.log('status', status);
  console.log(body.slice(0, Number(process.argv[4] ?? 800)));
}
