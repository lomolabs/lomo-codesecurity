import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants, createReadStream } from 'node:fs';
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  rename,
  rm,
  stat,
} from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import yauzl from 'yauzl';
import yazl from 'yazl';

const MAX_PACKAGE_BYTES = 2 * 1024 * 1024;
const CANONICAL_MEMBER_MTIME = new Date(1980, 0, 1, 0, 0, 0, 0);
const CANONICAL_MEMBER_MODE = 0o100644;
const ALLOWED_FILES = new Set([
  '[Content_Types].xml',
  'extension.vsixmanifest',
  'extension/LICENSE.txt',
  'extension/dist/extension.js',
  'extension/dist/git-push-cli.js',
  'extension/media/lomo-icon.png',
  'extension/media/lomo-view.svg',
  'extension/media/setup-backend.md',
  'extension/media/setup-connection.md',
  'extension/media/setup-repositories.md',
  'extension/media/setup-scan.md',
  'extension/media/setup-review.md',
  'extension/media/setup-protection.md',
  'extension/package.json',
  'extension/readme.md',
]);
const PRIVATE_TEXT = [
  /\/Users\//,
  /\/home\/[^/\s]+\//,
  /192\.168\.\d{1,3}\.\d{1,3}/,
  /fixture-capability/,
  /one-time-fixture/,
];

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const extensionRoot = resolve(scriptDirectory, '..');
const repoRoot = resolve(extensionRoot, '..', '..');
const packageJson = JSON.parse(await readFile(resolve(extensionRoot, 'package.json'), 'utf8'));
const outputDirectory = resolve(repoRoot, '.kodesec-test', 'vscode');
const outputPath = resolve(outputDirectory, `code-security-${packageJson.version}.vsix`);

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length === 4 && args[0] === '--audit-vsix' && args[2] === '--expected-sha256') {
    console.log(JSON.stringify(await auditVsix(args[1], args[3]), null, 2));
  } else if (args.length === 0) {
    await packageExtension();
  } else {
    throw new Error('Usage: package.mjs [--audit-vsix PATH --expected-sha256 SHA256]');
  }
}

async function packageExtension() {
  const sourceIdentity = sourceProvenance();

  execFileSync('npm', ['run', 'typecheck'], { cwd: extensionRoot, stdio: 'inherit' });
  execFileSync('npm', ['run', 'build'], { cwd: extensionRoot, stdio: 'inherit' });
  await mkdir(outputDirectory, { mode: 0o700, recursive: true });
  const stagingDirectory = await mkdtemp(resolve(outputDirectory, '.package-'));
  try {
    const generatedPath = resolve(stagingDirectory, 'generated.vsix');
    execFileSync(
      resolve(extensionRoot, 'node_modules', '.bin', 'vsce'),
      ['package', '--allow-missing-repository', '--out', generatedPath],
      { cwd: extensionRoot, stdio: 'inherit' },
    );

    const generatedArchive = await readBoundedArchive(generatedPath);
    assertPackage(packageJson, generatedArchive);
    const canonicalPath = resolve(stagingDirectory, 'canonical.vsix');
    await writeCanonicalArchive(canonicalPath, generatedArchive);
    const canonicalArchive = await readBoundedArchive(canonicalPath);
    assertPackage(packageJson, canonicalArchive);
    assertCanonicalArchive(canonicalArchive);
    assertCanonicalEndOfCentralDirectory(await readFile(canonicalPath));
    if (sourceProvenance() !== sourceIdentity) {
      throw new Error('Source inputs changed during extension packaging; no package was activated.');
    }
    await rename(canonicalPath, outputPath);
  } finally {
    await rm(stagingDirectory, { force: true, recursive: true });
  }

  const packageStat = await stat(outputPath);
  const archive = await readBoundedArchive(outputPath);
  assertPackage(packageJson, archive);
  assertCanonicalArchive(archive);
  assertCanonicalEndOfCentralDirectory(await readFile(outputPath));
  const digest = await sha256(outputPath);
  const contentCandidatePath = resolve(
    outputDirectory,
    'candidates',
    digest,
    `code-security-${packageJson.version}.vsix`,
  );
  await retainContentAddressedCandidate(outputPath, contentCandidatePath, digest, packageStat.size);
  console.log(`Verified ${outputPath}`);
  console.log(`Extension: ${packageJson.publisher}.${packageJson.name}`);
  console.log(`Files: ${archive.size}; bytes: ${packageStat.size}; sha256: ${digest}`);
}

function sourceProvenance() {
  return execFileSync(
    'python3',
    [resolve(repoRoot, 'scripts/source_provenance.py'), '--json', '--scope', 'extensions/vscode'],
    { cwd: repoRoot, encoding: 'utf8', timeout: 30_000, maxBuffer: 4096 },
  ).trim();
}

/** Recheck one already-built artifact without rebuilding, installing or extracting
 * it. Parse exactly the bounded bytes whose digest the caller supplied. */
export async function auditVsix(path, expectedSha256) {
  if (!/^[a-f0-9]{64}$/u.test(expectedSha256 ?? '')) throw new Error('Exact VSIX SHA256 required.');
  const selected = await lstat(path);
  if (!selected.isFile() || selected.isSymbolicLink()) throw new Error('VSIX must be a regular non-linked file.');
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  let content;
  try {
    const before = await file.stat();
    if (!before.isFile() || before.size > MAX_PACKAGE_BYTES) throw new Error('VSIX must be a bounded regular file.');
    if (before.dev !== selected.dev || before.ino !== selected.ino) throw new Error('VSIX identity changed before reading.');
    const buffer = Buffer.alloc(MAX_PACKAGE_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await file.read(buffer, length, buffer.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    const after = await file.stat();
    const current = await lstat(path);
    if (length !== before.size || after.size !== before.size || after.mtimeMs !== before.mtimeMs
      || after.ctimeMs !== before.ctimeMs || current.isSymbolicLink()
      || current.dev !== before.dev || current.ino !== before.ino) throw new Error('VSIX changed during the bounded read.');
    content = buffer.subarray(0, length);
  } finally {
    await file.close();
  }
  const digest = createHash('sha256').update(content).digest('hex');
  if (digest !== expectedSha256) throw new Error('VSIX digest differs from the reviewed candidate.');
  const archive = await readArchive(content);
  assertPackage(packageJson, archive);
  assertCanonicalArchive(archive);
  assertCanonicalEndOfCentralDirectory(content);
  return {
    schema: 'lomo-vsix-package-audit/v1', passed: true, platform_qualified: false,
    candidate: { sha256: digest, bytes: content.length,
      identity: `${packageJson.publisher}.${packageJson.name}@${packageJson.version}` },
    scope: 'member-boundary-private-text-and-canonical-metadata',
    members: [...archive].map(([path, { content: bytes }]) => ({ path, bytes: bytes.length,
      sha256: createHash('sha256').update(bytes).digest('hex') })),
    rebuilt: false, installed: false, extracted: false,
  };
}

async function retainContentAddressedCandidate(sourcePath, contentPath, expectedSha256, expectedBytes) {
  await mkdir(dirname(contentPath), { recursive: true, mode: 0o700 });
  try {
    await assertImmutableContent(contentPath, expectedSha256, expectedBytes);
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error;
    await copyFile(sourcePath, contentPath, constants.COPYFILE_EXCL);
    await chmod(contentPath, 0o600);
  }
  const [sourceMetadata, contentMetadata] = await Promise.all([
    lstat(sourcePath),
    lstat(contentPath),
  ]);
  if (
    sourceMetadata.nlink !== 1
    || contentMetadata.nlink !== 1
    || (sourceMetadata.dev === contentMetadata.dev && sourceMetadata.ino === contentMetadata.ino)
  ) {
    throw new Error('VSIX convenience output and content candidate must be independent files');
  }
}

async function assertImmutableContent(path, expectedSha256, expectedBytes) {
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size !== expectedBytes) {
    throw new Error(`Content-addressed artifact has unexpected metadata: ${path}`);
  }
  const actualSha256 = await sha256(path);
  if (actualSha256 !== expectedSha256) {
    throw new Error(`Content-addressed artifact has unexpected bytes: ${path}`);
  }
}

async function readBoundedArchive(path) {
  const packageStat = await stat(path);
  if (packageStat.size > MAX_PACKAGE_BYTES) {
    throw new Error(`VSIX is ${packageStat.size} bytes; maximum is ${MAX_PACKAGE_BYTES}.`);
  }
  return readArchive(path);
}

function readArchive(path) {
  return new Promise((resolveArchive, rejectArchive) => {
    const read = Buffer.isBuffer(path) ? yauzl.fromBuffer : yauzl.open;
    read(path, { lazyEntries: true }, (openError, zipfile) => {
      if (openError || !zipfile) {
        rejectArchive(openError || new Error('VSIX could not be opened.'));
        return;
      }
      const entries = new Map();
      let unpackedBytes = 0;
      const fail = (error) => {
        zipfile.close();
        rejectArchive(error);
      };
      zipfile.on('error', fail);
      zipfile.on('entry', (entry) => {
        if (!ALLOWED_FILES.has(entry.fileName)) {
          fail(new Error(`VSIX member allowlist mismatch: ${entry.fileName}`));
          return;
        }
        if (entry.fileName.endsWith('/')) {
          fail(new Error(`VSIX contains unexpected directory member: ${entry.fileName}`));
          return;
        }
        zipfile.openReadStream(entry, (streamError, stream) => {
          if (streamError || !stream) {
            fail(streamError || new Error(`VSIX member could not be read: ${entry.fileName}`));
            return;
          }
          const chunks = [];
          let size = 0;
          stream.on('data', (chunk) => {
            size += chunk.length;
            unpackedBytes += chunk.length;
            if (size > MAX_PACKAGE_BYTES || unpackedBytes > MAX_PACKAGE_BYTES) {
              stream.destroy(new Error(`VSIX expansion exceeds package bound: ${entry.fileName}`));
              return;
            }
            chunks.push(chunk);
          });
          stream.on('error', fail);
          stream.on('end', () => {
            if (entries.has(entry.fileName)) {
              fail(new Error(`VSIX contains duplicate member: ${entry.fileName}`));
              return;
            }
            entries.set(entry.fileName, {
              content: Buffer.concat(chunks),
              metadata: {
                compressionMethod: entry.compressionMethod,
                externalFileAttributes: entry.externalFileAttributes,
                extraFieldCount: entry.extraFields.length,
                fileCommentLength: entry.fileComment.length,
                generalPurposeBitFlag: entry.generalPurposeBitFlag,
                lastModFileDate: entry.lastModFileDate,
                lastModFileTime: entry.lastModFileTime,
                versionMadeBy: entry.versionMadeBy,
                versionNeededToExtract: entry.versionNeededToExtract,
              },
            });
            zipfile.readEntry();
          });
        });
      });
      zipfile.on('end', () => resolveArchive(entries));
      zipfile.readEntry();
    });
  });
}

function assertPackage(manifest, archive) {
  const identity = `${manifest.publisher}.${manifest.name}`;
  if (identity !== 'lomo-dev.code-security') {
    throw new Error(`Unexpected extension identity: ${identity}`);
  }
  const actualFiles = [...archive.keys()].sort();
  const expectedFiles = [...ALLOWED_FILES].sort();
  const unpackedBytes = [...archive.values()].reduce((total, entry) => total + entry.content.length, 0);
  if (unpackedBytes > MAX_PACKAGE_BYTES) {
    throw new Error(`VSIX expands to ${unpackedBytes} bytes; maximum is ${MAX_PACKAGE_BYTES}.`);
  }
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error(`VSIX member allowlist mismatch:\n${actualFiles.join('\n')}`);
  }
  if (!archive.has('extension/dist/extension.js')) {
    throw new Error('VSIX is missing the production extension bundle.');
  }
  const packagedManifest = JSON.parse(archive.get('extension/package.json').content.toString('utf8'));
  if (`${packagedManifest.publisher}.${packagedManifest.name}` !== identity) {
    throw new Error('Packaged extension identity differs from source package.json.');
  }
  if (packagedManifest.version !== manifest.version) {
    throw new Error('Packaged extension version differs from source package.json.');
  }
  if (packagedManifest.main !== './dist/extension.js') {
    throw new Error('Packaged extension entry point is not the production bundle.');
  }
  const vsixManifest = archive.get('extension.vsixmanifest').content.toString('utf8');
  for (const [attribute, value] of [
    ['Id', manifest.name],
    ['Publisher', manifest.publisher],
    ['Version', manifest.version],
  ]) {
    const escaped = value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    if (!new RegExp(`<Identity[^>]*\\b${attribute}="${escaped}"`).test(vsixManifest)) {
      throw new Error(`VSIX identity is missing ${attribute}="${value}".`);
    }
  }
  for (const [file, entry] of archive) {
    if (/\.(?:js|json|md|txt|xml|vsixmanifest)$/i.test(file)) {
      const text = entry.content.toString('utf8');
      for (const pattern of PRIVATE_TEXT) {
        if (pattern.test(text)) {
          throw new Error(`VSIX member contains private environment text: ${file}`);
        }
      }
    }
  }
}

function assertCanonicalArchive(archive) {
  const canonicalNames = [...ALLOWED_FILES].sort();
  if (JSON.stringify([...archive.keys()]) !== JSON.stringify(canonicalNames)) {
    throw new Error('Canonical VSIX member order differs from the sorted allowlist.');
  }
  const expectedMode = (CANONICAL_MEMBER_MODE << 16) >>> 0;
  for (const [file, { metadata }] of archive) {
    if (
      metadata.versionMadeBy !== 0x033f
      || metadata.versionNeededToExtract !== 20
      || metadata.generalPurposeBitFlag !== 0x0800
      || metadata.compressionMethod !== 0
      || metadata.lastModFileTime !== 0
      || metadata.lastModFileDate !== 33
      || metadata.externalFileAttributes !== expectedMode
      || metadata.extraFieldCount !== 0
      || metadata.fileCommentLength !== 0
    ) {
      throw new Error(`VSIX member metadata is not canonical: ${file}`);
    }
  }
}

function assertCanonicalEndOfCentralDirectory(content) {
  const endOfCentralDirectorySize = 22;
  const offset = content.length - endOfCentralDirectorySize;
  if (
    offset < 0
    || content.readUInt32LE(offset) !== 0x06054b50
    || content.readUInt16LE(offset + 4) !== 0
    || content.readUInt16LE(offset + 6) !== 0
    || content.readUInt16LE(offset + 8) !== ALLOWED_FILES.size
    || content.readUInt16LE(offset + 10) !== ALLOWED_FILES.size
    || content.readUInt16LE(offset + 20) !== 0
  ) {
    throw new Error('VSIX end-of-central-directory metadata is not canonical.');
  }
}

async function writeCanonicalArchive(path, archive) {
  const zipfile = new yazl.ZipFile();
  const chunks = [];
  let size = 0;
  const archiveComplete = new Promise((resolveArchive, rejectArchive) => {
    zipfile.on('error', rejectArchive);
    zipfile.outputStream.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_PACKAGE_BYTES) {
        zipfile.outputStream.destroy(new Error(`Canonical VSIX exceeds ${MAX_PACKAGE_BYTES} bytes.`));
        return;
      }
      chunks.push(chunk);
    });
    zipfile.outputStream.on('error', rejectArchive);
    zipfile.outputStream.on('end', () => resolveArchive(Buffer.concat(chunks)));
  });

  for (const file of [...archive.keys()].sort()) {
    zipfile.addBuffer(archive.get(file).content, file, {
      compress: false,
      mode: CANONICAL_MEMBER_MODE,
      mtime: CANONICAL_MEMBER_MTIME,
    });
  }
  zipfile.end();
  const content = await archiveComplete;
  const file = await open(
    path,
    constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY | constants.O_NOFOLLOW,
    0o600,
  );
  try {
    await file.writeFile(content);
    await file.sync();
  } finally {
    await file.close();
  }
}

async function sha256(path) {
  const hash = createHash('sha256');
  await new Promise((resolveHash, rejectHash) => {
    createReadStream(path)
      .on('error', rejectHash)
      .on('data', (chunk) => hash.update(chunk))
      .on('end', resolveHash);
  });
  return hash.digest('hex');
}
