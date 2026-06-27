#!/usr/bin/env node
import {mkdir, readFile, writeFile} from 'node:fs/promises';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const MODEL = 'gpt-4o-mini-tts';
const OUTPUT_FORMAT = 'wav';
const ALLOWED_VOICES = new Set(['cedar', 'marin']);
const TTS_INSTRUCTIONS =
  'Speak in a calm, technical, confident tone. Use neutral international English. Keep a steady pace with short pauses between ideas. Do not sound dramatic or salesy.';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const scriptPath = path.join(root, 'voiceover', 'script.md');
const outputPath = path.join(root, 'assets', 'audio', 'voiceover.wav');

const voice = process.argv[2];

if (!ALLOWED_VOICES.has(voice)) {
  console.error('Usage: node scripts/generate-voiceover.mjs <cedar|marin>');
  process.exit(1);
}

if (!process.env.OPENAI_API_KEY) {
  console.error('OPENAI_API_KEY is required to generate voiceover audio.');
  process.exit(1);
}

const rawScript = await readFile(scriptPath, 'utf8');
const input = rawScript
  .split('\n')
  .filter(line => !line.startsWith('#'))
  .join('\n')
  .replace(/\n{3,}/g, '\n\n')
  .trim();

if (!input) {
  console.error(`Voiceover script is empty: ${scriptPath}`);
  process.exit(1);
}

const response = await fetch('https://api.openai.com/v1/audio/speech', {
  method: 'POST',
  headers: {
    Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
    'Content-Type': 'application/json',
  },
  body: JSON.stringify({
    model: MODEL,
    voice,
    input,
    instructions: TTS_INSTRUCTIONS,
    response_format: OUTPUT_FORMAT,
  }),
});

if (!response.ok) {
  const body = await response.text();
  console.error(`OpenAI TTS request failed: ${response.status} ${response.statusText}`);
  console.error(body);
  process.exit(1);
}

const audio = Buffer.from(await response.arrayBuffer());
await mkdir(path.dirname(outputPath), {recursive: true});
await writeFile(outputPath, audio);

console.log(`Wrote ${path.relative(root, outputPath)} using ${MODEL}/${voice}.`);
