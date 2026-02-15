import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { createApiHandler } from '../worker.js';
import { createQaEnv } from './fixtures/maths-env.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, '..');
const distDir = path.join(repoRoot, 'dist');

const PORT = Number(process.env.PORT || 8789);
const ORIGIN = `http://127.0.0.1:${PORT}`;

const { env } = await createQaEnv(ORIGIN);
const apiHandler = createApiHandler();

const realFetch = globalThis.fetch;
if (typeof realFetch === 'function') {
  globalThis.fetch = async (input, init) => {
    const url = typeof input === 'string'
      ? input
      : (input && typeof input.url === 'string' ? input.url : '');

    if (url === 'https://api.openai.com/v1/responses') {
      const headers = new Headers(init?.headers || (input && input.headers) || {});
      const auth = String(headers.get('Authorization') || '');
      const expected = `Bearer ${String(env.OPENAI_API_KEY || '')}`;

      if (!expected || auth !== expected) {
        return new Response(
          JSON.stringify({ error: { message: 'QA stub: missing/invalid OpenAI API key.' } }),
          { status: 401, headers: { 'Content-Type': 'application/json; charset=utf-8' } }
        );
      }

      let bodyText = '';
      try {
        const body = init?.body;
        if (typeof body === 'string') bodyText = body;
        else if (body instanceof Uint8Array) bodyText = Buffer.from(body).toString('utf8');
        else if (body instanceof ArrayBuffer) bodyText = Buffer.from(body).toString('utf8');
        else if (body != null) bodyText = String(body);
      } catch {
        bodyText = '';
      }

      let schemaName = '';
      try {
        const parsed = bodyText ? JSON.parse(bodyText) : null;
        schemaName = String(parsed?.text?.format?.name || '');
      } catch {
        schemaName = '';
      }

      const output = schemaName === 'mark_answer'
        ? { score: 1, max: 2, reasoning: 'QA stub feedback: clear point and relevant paraphrase.' }
        : { quote: 'almond trees', lineNumber: 1 };

      return new Response(
        JSON.stringify({ output_text: JSON.stringify(output) }),
        { status: 200, headers: { 'Content-Type': 'application/json; charset=utf-8' } }
      );
    }

    return realFetch(input, init);
  };
}

function contentTypeForPath(p) {
  const lower = String(p).toLowerCase();
  if (lower.endsWith('.html')) return 'text/html; charset=utf-8';
  if (lower.endsWith('.js')) return 'application/javascript; charset=utf-8';
  if (lower.endsWith('.mjs')) return 'application/javascript; charset=utf-8';
  if (lower.endsWith('.css')) return 'text/css; charset=utf-8';
  if (lower.endsWith('.json')) return 'application/json; charset=utf-8';
  if (lower.endsWith('.png')) return 'image/png';
  if (lower.endsWith('.pdf')) return 'application/pdf';
  return 'application/octet-stream';
}

async function readBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
}

async function handleApi(req, res, url) {
  const headers = new Headers();
  for (const [key, value] of Object.entries(req.headers)) {
    if (value == null) continue;
    if (Array.isArray(value)) headers.set(key, value.join(','));
    else headers.set(key, value);
  }

  const body = ['GET', 'HEAD'].includes(req.method || '') ? undefined : await readBody(req);
  const request = new Request(`${ORIGIN}${url.pathname}${url.search}`, {
    method: req.method,
    headers,
    body,
  });

  const response = await apiHandler.fetch(request, env);

  res.statusCode = response.status;

  const setCookies = typeof response.headers.getSetCookie === 'function'
    ? response.headers.getSetCookie()
    : (response.headers.get('set-cookie') ? [response.headers.get('set-cookie')] : []);

  response.headers.forEach((value, key) => {
    if (key.toLowerCase() === 'set-cookie') return;
    res.setHeader(key, value);
  });
  if (setCookies.length) {
    res.setHeader('Set-Cookie', setCookies);
  }

  const arrayBuffer = await response.arrayBuffer();
  res.end(Buffer.from(arrayBuffer));
}

async function serveStatic(req, res, pathname) {
  const cleanPath = pathname.split('?')[0];

  const tryFiles = [];
  if (cleanPath === '/' || cleanPath === '') {
    tryFiles.push(path.join(distDir, 'index.html'));
  } else {
    const target = cleanPath.startsWith('/') ? cleanPath.slice(1) : cleanPath;
    tryFiles.push(path.join(distDir, target));
    if (cleanPath.endsWith('/')) {
      tryFiles.push(path.join(distDir, target, 'index.html'));
    }
  }

  // SPA rewrite for /maths/*.
  if (cleanPath === '/maths' || cleanPath === '/maths/' || cleanPath.startsWith('/maths/')) {
    tryFiles.push(path.join(distDir, 'maths', 'index.html'));
  }

  // Existing /ruae stays a standalone page.
  if (cleanPath === '/ruae' || cleanPath === '/ruae/' || cleanPath.startsWith('/ruae/')) {
    tryFiles.push(path.join(distDir, 'ruae', 'index.html'));
  }

  for (const filePath of tryFiles) {
    try {
      const data = await readFile(filePath);
      res.statusCode = 200;
      res.setHeader('Content-Type', contentTypeForPath(filePath));
      res.end(data);
      return;
    } catch {
      // try next
    }
  }

  res.statusCode = 404;
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.end('Not found');
}

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url || '/', ORIGIN);

    if (url.pathname === '/healthz' || url.pathname.startsWith('/api/')) {
      await handleApi(req, res, url);
      return;
    }

    await serveStatic(req, res, url.pathname);
  } catch (error) {
    res.statusCode = 500;
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.end(String(error?.stack || error));
  }
});

server.listen(PORT, '127.0.0.1', () => {
  process.stdout.write(`qa server listening on ${ORIGIN}\n`);
});
