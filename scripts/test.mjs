// scripts/test.mjs
// Starts the app on a free port, runs the exploit suite and the extra
// hardening checks against it, then shuts it down.
//
//   npm test
//
// Exits non-zero if any exploit still works or any check fails, so it can
// gate a CI pipeline.
import { spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

function freePort() {
  return new Promise((resolve) => {
    const srv = createServer().listen(0, () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

async function waitForServer(url, attempts = 50) {
  for (let i = 0; i < attempts; i++) {
    try {
      await fetch(url);
      return;
    } catch {
      await new Promise((r) => setTimeout(r, 200));
    }
  }
  throw new Error(`server did not start at ${url}`);
}

const port = await freePort();
const target = `http://localhost:${port}`;
const server = spawn(process.execPath, [join(root, 'server.js')], {
  env: { ...process.env, PORT: String(port) },
  stdio: ['ignore', 'inherit', 'inherit'],
});

let failed = false;
try {
  await waitForServer(target);
  for (const script of ['exploits/run-all.mjs', 'tests/hardening-checks.mjs']) {
    const r = spawnSync(process.execPath, [join(root, script)], {
      stdio: 'inherit',
      env: { ...process.env, TARGET: target },
    });
    if (r.status !== 0) failed = true;
  }
} catch (e) {
  console.error(e.message);
  failed = true;
} finally {
  server.kill();
}

process.exit(failed ? 1 : 0);
