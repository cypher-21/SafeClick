const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT_DIR = path.resolve(__dirname, '..');
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT_DIR, 'manifest.json'), 'utf8'));
const version = manifest.version || '2.0.0';

console.log(`📦 Packaging SafeClick v${version} for Chrome Web Store...`);

const stagingDir = path.join(ROOT_DIR, 'dist_webstore_staging');
if (fs.existsSync(stagingDir)) {
  fs.rmSync(stagingDir, { recursive: true, force: true });
}
fs.mkdirSync(stagingDir, { recursive: true });

// Items to include in the Chrome Web Store production package
const includeItems = [
  'manifest.json',
  'background.js',
  'config.js',
  'content.css',
  'interstitial.css',
  'interstitial.html',
  'interstitial.js',
  'onboarding.css',
  'onboarding.html',
  'onboarding.js',
  'phishtank.js',
  'popup.css',
  'popup.html',
  'popup.js',
  'reputation-db.js',
  'trust-scorer.js',
  'LICENSE',
  'NOTICE',
  'PRIVACY.md',
  'README.md',
  'THIRD_PARTY_NOTICES.md',
  '_locales',
  'ai',
  'content',
  'core',
  'data',
  'evidence',
  'icons',
  'ml',
  'modules',
  'scoring'
];

// Helper to copy recursively
function copyRecursive(src, dest) {
  const stat = fs.statSync(src);
  if (stat.isDirectory()) {
    fs.mkdirSync(dest, { recursive: true });
    for (const child of fs.readdirSync(src)) {
      copyRecursive(path.join(src, child), path.join(dest, child));
    }
  } else {
    fs.copyFileSync(src, dest);
  }
}

for (const item of includeItems) {
  const srcPath = path.join(ROOT_DIR, item);
  const destPath = path.join(stagingDir, item);
  if (fs.existsSync(srcPath)) {
    copyRecursive(srcPath, destPath);
    console.log(`  ✓ Included: ${item}`);
  } else {
    console.warn(`  ⚠️ Warning: Item not found: ${item}`);
  }
}

const targetZip1 = path.join(ROOT_DIR, `safeclick-v${version}-webstore.zip`);
const targetZip2 = path.join(ROOT_DIR, 'SafeClick.zip');

for (const z of [targetZip1, targetZip2]) {
  if (fs.existsSync(z)) {
    fs.rmSync(z, { force: true });
  }
}

// Compress using PowerShell Compress-Archive
console.log('🗜️  Compressing files into root-level zip archives...');
const psCommand = `Compress-Archive -Path '${stagingDir}\\*' -DestinationPath '${targetZip1}' -Force; Copy-Item -Path '${targetZip1}' -Destination '${targetZip2}' -Force`;

execFileSync('powershell.exe', ['-NoProfile', '-Command', psCommand], { stdio: 'inherit' });

// Clean up staging folder
fs.rmSync(stagingDir, { recursive: true, force: true });

// Inspect the generated zip files
const size1 = (fs.statSync(targetZip1).size / 1024).toFixed(1);
const size2 = (fs.statSync(targetZip2).size / 1024).toFixed(1);

console.log(`\n🎉 Chrome Web Store packages successfully built:`);
console.log(`  1. ${path.basename(targetZip1)} (${size1} KB)`);
console.log(`  2. ${path.basename(targetZip2)} (${size2} KB)`);

// Verify manifest is at zip root and print entries
const verifyScript = `
Add-Type -AssemblyName System.IO.Compression.FileSystem;
$zip = [System.IO.Compression.ZipFile]::OpenRead('${targetZip1.replace(/\\/g, '\\\\')}');
$entries = $zip.Entries | Select-Object -ExpandProperty FullName | Sort-Object;
Write-Host '--- ZIP Archive Contents ---';
$entries | ForEach-Object { Write-Host ('  ' + $_) };
$hasManifest = $entries -contains 'manifest.json';
Write-Host '----------------------------';
Write-Host ('Total Entries: ' + $entries.Count);
Write-Host ('manifest.json at root: ' + $hasManifest);
$zip.Dispose();
`;

execFileSync('powershell.exe', ['-NoProfile', '-Command', verifyScript], { stdio: 'inherit' });

