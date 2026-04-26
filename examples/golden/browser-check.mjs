import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { loadArtifactFromBundle } from '../../packages/logicpearl-browser/src/index.js';

const [artifactDir, inputPath] = process.argv.slice(2);

if (!artifactDir || !inputPath) {
  console.error('usage: node examples/golden/browser-check.mjs <artifact-dir> <input.json>');
  process.exit(2);
}

const manifest = JSON.parse(await readFile(join(artifactDir, 'artifact.json'), 'utf8'));
const wasmPath = manifest.files?.wasm;
const wasmMetadataPath = manifest.files?.wasm_metadata;

if (!wasmPath || !wasmMetadataPath) {
  throw new Error('artifact must be compiled to Wasm first');
}

const wasmBytes = await readFile(join(artifactDir, wasmPath));
const wasmMetadata = JSON.parse(await readFile(join(artifactDir, wasmMetadataPath), 'utf8'));
const input = JSON.parse(await readFile(inputPath, 'utf8'));

const artifact = await loadArtifactFromBundle({
  manifest,
  wasmModule: wasmBytes.buffer.slice(
    wasmBytes.byteOffset,
    wasmBytes.byteOffset + wasmBytes.byteLength
  ),
  wasmMetadata,
});

console.log(JSON.stringify(artifact.evaluateJson(input), null, 2));
