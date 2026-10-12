// Compatibility runner for the React DOM regression suite. These tests render
// real React + Material UI + Emotion in jsdom, not a handwritten DOM emulator.
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const result = spawnSync('pnpm', ['test'], {
  cwd: path.join(__dirname, '..', 'web'),
  stdio: 'inherit',
  env: process.env,
});
if (result.error) {
  console.error('Unable to run frontend tests. Install Node 24 and pnpm@latest, then run pnpm --dir web install --frozen-lockfile first.');
  console.error(result.error.message);
}
process.exitCode = result.status ?? 1;
