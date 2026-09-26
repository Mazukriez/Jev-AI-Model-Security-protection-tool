import http from 'node:http';
import { scan } from '../index.js';

const port = Number(process.env.PORT ?? 8787);
const host = process.env.HOST ?? '0.0.0.0';

function json(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff' });
  res.end(JSON.stringify(body));
}

const server = http.createServer(async (req, res) => {
  if (req.method === 'GET' && req.url === '/api/health') return json(res, 200, { ok: true, service: 'jevshield', version: '0.2.0' });
  if (req.method !== 'POST' || req.url !== '/api/scan') return json(res, 404, { error: 'not_found' });
  let body = '';
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > 1_000_000) return json(res, 413, { error: 'payload_too_large' });
  }
  try {
    const input = JSON.parse(body || '{}');
    return json(res, 200, scan(input, { includeEvidence: false }));
  } catch (error) {
    return json(res, 400, { error: 'invalid_json', detail: error instanceof Error ? error.message : 'invalid request' });
  }
});

server.listen(port, host, () => console.log(`JevShield listening on http://${host}:${port}`));
