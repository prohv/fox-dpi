/**
 * Fox DPI Post-Install & On-Demand Downloader
 * Downloads the pre-built, compressed binary for the current OS and architecture from GitHub Releases.
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const { execSync } = require('child_process');

const VERSION = 'v0.1.2';
const REPO = 'prohv/fox-dpi';

const PLATFORM_MAP = {
  win32: 'windows',
  linux: 'linux',
  darwin: 'darwin',
};

const ARCH_MAP = {
  x64: 'amd64',
  arm64: 'arm64',
};

function getPlatformInfo() {
  const osType = PLATFORM_MAP[process.platform];
  const arch = ARCH_MAP[process.arch];

  if (!osType || !arch) {
    throw new Error(`Unsupported platform or architecture: ${process.platform} ${process.arch}`);
  }

  const isWindows = osType === 'windows';
  const ext = isWindows ? '.exe' : '';
  const archiveExt = isWindows ? 'zip' : 'tar.gz';
  const targetName = `${osType}-${arch}`;
  const binaryName = `foxdpi${ext}`;
  const archiveName = `foxdpi-${VERSION}-${targetName}.${archiveExt}`;
  const url = `https://github.com/${REPO}/releases/download/${VERSION}/${archiveName}`;

  return { osType, arch, isWindows, binaryName, archiveName, url };
}

function download(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);

    function get(reqUrl) {
      https.get(reqUrl, (res) => {
        // Handle HTTP redirects (GitHub Releases redirect to AWS S3)
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          return get(res.headers.location);
        }

        if (res.statusCode !== 200) {
          file.close();
          fs.unlink(dest, () => {});
          return reject(new Error(`Failed to download: HTTP ${res.statusCode} from ${reqUrl}`));
        }

        res.pipe(file);
        file.on('finish', () => {
          file.close(() => resolve());
        });
      }).on('error', (err) => {
        file.close();
        fs.unlink(dest, () => {});
        reject(err);
      });
    }

    get(url);
  });
}

async function ensureBinary() {
  const binDir = path.join(__dirname, '..', 'bin');
  if (!fs.existsSync(binDir)) {
    fs.mkdirSync(binDir, { recursive: true });
  }

  let info;
  try {
    info = getPlatformInfo();
  } catch (err) {
    console.warn(`[!] ${err.message}`);
    const fallback = tryGoBuildFallback(binDir);
    if (fallback) return fallback;
    throw err;
  }

  const targetBinary = path.join(binDir, info.binaryName);
  if (fs.existsSync(targetBinary)) {
    return targetBinary;
  }

  console.log(`[+] Fox DPI native binary not found. Fetching for ${info.osType}-${info.arch}...`);
  console.log(`[+] Downloading: ${info.url}`);

  const tempArchive = path.join(binDir, info.archiveName);

  try {
    await download(info.url, tempArchive);
    console.log(`[+] Download complete. Extracting...`);

    if (info.isWindows) {
      try {
        execSync(`tar -xf "${tempArchive}" -C "${binDir}"`, { stdio: 'ignore' });
      } catch {
        execSync(`powershell -Command "Expand-Archive -Path '${tempArchive}' -DestinationPath '${binDir}' -Force"`, { stdio: 'ignore' });
      }
    } else {
      execSync(`tar -xzf "${tempArchive}" -C "${binDir}"`, { stdio: 'ignore' });
    }

    if (fs.existsSync(tempArchive)) {
      fs.unlinkSync(tempArchive);
    }

    if (!info.isWindows && fs.existsSync(targetBinary)) {
      fs.chmodSync(targetBinary, 0o755);
    }

    console.log(`[✓] Fox DPI ${VERSION} ready: ${targetBinary}\n`);
    return targetBinary;
  } catch (err) {
    console.warn(`[!] Download from GitHub failed: ${err.message}`);
    console.log(`[*] Attempting local compilation fallback via 'go build'...`);
    const fallback = tryGoBuildFallback(binDir);
    if (fallback && fs.existsSync(fallback)) {
      return fallback;
    }
    throw new Error(`Failed to install Fox DPI native binary: ${err.message}`);
  }
}

function tryGoBuildFallback(binDir) {
  try {
    const isWindows = process.platform === 'win32';
    const binaryName = isWindows ? 'foxdpi.exe' : 'foxdpi';
    const outputPath = path.join(binDir, binaryName);

    console.log(`[*] Running: go build -ldflags="-s -w" -o "${outputPath}" ./cmd/foxdpi`);
    execSync(`go build -ldflags="-s -w" -o "${outputPath}" ./cmd/foxdpi`, {
      cwd: path.join(__dirname, '..'),
      stdio: 'inherit',
    });

    if (fs.existsSync(outputPath)) {
      if (!isWindows) {
        fs.chmodSync(outputPath, 0o755);
      }
      console.log(`[✓] Compiled from source successfully: ${outputPath}`);
      return outputPath;
    }
  } catch (buildErr) {
    console.warn(`[!] Local Go build unavailable: ${buildErr.message}`);
  }

  return null;
}

// If invoked directly via `node scripts/install.js` or `npm install` postinstall:
if (require.main === module) {
  ensureBinary().catch((err) => {
    console.warn(`[!] Post-install notice: ${err.message}`);
  });
}

module.exports = {
  ensureBinary,
  VERSION,
};
