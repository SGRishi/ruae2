import { cp, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');
const publicDir = path.join(rootDir, 'public');
const distDir = path.join(rootDir, 'dist');

/**
 * @param {string | undefined | null} value
 * @returns {string}
 */
function normalizeBaseUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  return raw.endsWith('/') ? raw.slice(0, -1) : raw;
}

function resolveApiBase() {
  const candidates = [
    process.env.API_BASE,
    process.env.VITE_API_BASE,
    process.env.NEXT_PUBLIC_API_BASE,
  ];

  for (const candidate of candidates) {
    const normalized = normalizeBaseUrl(candidate);
    if (normalized) return normalized;
  }

  return '';
}

async function run() {
  await mkdir(distDir, { recursive: true });
  await cp(publicDir, distDir, { recursive: true });

  const apiBase = resolveApiBase();
  // Only set API_BASE when explicitly configured. When omitted, the auth client
  // falls back to its production default (https://api.rishisubjects.co.uk) on
  // non-local hosts.
  const runtimeConfig = `window.__APP_CONFIG__ = window.__APP_CONFIG__ || {};\n${
    apiBase ? `window.__APP_CONFIG__.API_BASE = ${JSON.stringify(apiBase)};\n` : ''
  }`;
  await writeFile(path.join(distDir, 'runtime-config.js'), runtimeConfig, 'utf8');

  process.stdout.write(`Built frontend to dist/ with API_BASE=${apiBase || '(same origin)'}\n`);
}

run().catch((error) => {
  process.stderr.write(`${error?.stack || error}\n`);
  process.exit(1);
});
