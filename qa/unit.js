import { spawnSync } from 'node:child_process';
import { readdir } from 'node:fs/promises';
import path from 'node:path';

async function listTestFiles(dir) {
  const root = path.resolve(dir);
  const out = [];

  async function walk(current) {
    const entries = await readdir(current, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        await walk(fullPath);
        continue;
      }
      if (entry.isFile() && entry.name.endsWith('.test.mjs')) {
        out.push(fullPath);
      }
    }
  }

  await walk(root);
  out.sort();
  return out;
}

const files = await listTestFiles('tests');
if (!files.length) {
  console.error('No unit/integration tests found under tests/.');
  process.exit(1);
}

const result = spawnSync(process.execPath, ['--test', ...files], { stdio: 'inherit' });
process.exit(result.status == null ? 1 : result.status);
