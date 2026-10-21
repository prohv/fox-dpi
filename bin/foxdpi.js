#!/usr/bin/env node

/**
 * Fox DPI Launcher Wrapper
 * Forwards execution directly to the platform-native Go binary.
 */

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const isWindows = process.platform === 'win32';
const binaryName = isWindows ? 'foxdpi.exe' : 'foxdpi';
const binaryPath = path.join(__dirname, binaryName);

if (!fs.existsSync(binaryPath)) {
  console.error(`\x1b[31m[!] Fox DPI binary not found at: ${binaryPath}\x1b[0m`);
  console.error(`    Please run 'npm install' or 'node scripts/install.js' to fetch the native binary.`);
  process.exit(1);
}

const child = spawn(binaryPath, process.argv.slice(2), {
  stdio: 'inherit',
  windowsHide: false,
});

// Forward termination signals
process.on('SIGINT', () => {
  if (!isWindows && child.pid) {
    child.kill('SIGINT');
  }
});

process.on('SIGTERM', () => {
  if (child.pid) {
    child.kill('SIGTERM');
  }
});

child.on('exit', (code, signal) => {
  if (signal) {
    process.kill(process.pid, signal);
  } else {
    process.exit(code || 0);
  }
});

child.on('error', (err) => {
  console.error(`\x1b[31m[!] Failed to execute Fox DPI: ${err.message}\x1b[0m`);
  process.exit(1);
});
