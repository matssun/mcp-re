#!/usr/bin/env node
import {access, mkdir} from 'node:fs/promises';
import {constants} from 'node:fs';
import {spawn} from 'node:child_process';
import path from 'node:path';
import {createRequire} from 'node:module';
import {fileURLToPath} from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const root = path.resolve(__dirname, '..');
const dist = path.join(root, 'dist');
const silentVideo = path.join(dist, 'mcps-intro-silent.mp4');
const frameDirs = [
  path.join(root, 'output', 'still', 'mcps-intro-silent'),
  path.join(root, 'output', 'still', 'mcps-intro'),
];
const frameExtensions = ['png', 'jpg', 'jpeg', 'webp'];
const voiceover = path.join(root, 'assets', 'audio', 'voiceover.wav');
const finalVideo = path.join(dist, 'mcps-intro-with-voice.mp4');
const ffmpegPath = require('@ffmpeg-installer/ffmpeg').path;

async function assertReadable(file, message) {
  try {
    await access(file, constants.R_OK);
  } catch {
    console.error(message);
    console.error(`Missing file: ${path.relative(root, file)}`);
    process.exit(1);
  }
}

async function resolveVideoInput() {
  try {
    await access(silentVideo, constants.R_OK);
    return {type: 'video', input: silentVideo};
  } catch {
    // fall through to frame-sequence inputs
  }

  for (const frameDir of frameDirs) {
    for (const extension of frameExtensions) {
      const frameFile = path.join(frameDir, `000001.${extension}`);
      try {
        await access(frameFile, constants.R_OK);
        return {type: 'frames', input: frameDir, extension};
      } catch {
        // continue
      }
    }
  }

  console.error('No silent render found.');
  console.error('Export the Motion Canvas scene sequence first, or create dist/mcps-intro-silent.mp4.');
  console.error('Look for frames under output/still/mcps-intro-silent or output/still/mcps-intro.');
  process.exit(1);
}

await assertReadable(
  voiceover,
  'Voiceover audio is required before muxing. Run npm run voiceover:cedar or npm run voiceover:marin.',
);

await mkdir(dist, {recursive: true});

const source = await resolveVideoInput();
const args =
  source.type === 'video'
    ? [
        '-y',
        '-i',
        source.input,
        '-i',
        voiceover,
        '-map',
        '0:v:0',
        '-map',
        '1:a:0',
        '-c:v',
        'copy',
        '-c:a',
        'aac',
        '-shortest',
        finalVideo,
      ]
    : [
        '-y',
        '-framerate',
        '60',
        '-i',
        path.join(source.input, `%06d.${source.extension}`),
        '-i',
        voiceover,
        '-map',
        '0:v:0',
        '-map',
        '1:a:0',
        '-c:v',
        'libx264',
        '-pix_fmt',
        'yuv420p',
        '-c:a',
        'aac',
        '-shortest',
        finalVideo,
      ];

const ffmpeg = spawn(ffmpegPath, args, {stdio: 'inherit'});

ffmpeg.on('exit', code => {
  if (code === 0) {
    console.log(`Wrote ${path.relative(root, finalVideo)}.`);
    return;
  }

  console.error(`ffmpeg exited with code ${code}.`);
  process.exit(code ?? 1);
});
