// Assemble the final cut: [preamble + SFX] -> [existing narrated video].
//
// The existing video (dist/mcps-intro-with-voice.mp4) is NOT re-timed or
// re-rendered here — it is only prepended with the preamble. The preamble's
// audio is sourced straight from the SFX wav, so this works whether the
// editor exported the preamble with or without an embedded audio track.
//
// Inputs:
//   dist/preamble.mp4                  (export the `mcps-preamble` project via the editor)
//   assets/audio/intro-analog-to-quantum.wav
//   dist/mcps-intro-with-voice.mp4     (your finished narrated video)
// Output:
//   dist/mcps-intro-final.mp4

import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';

const PREAMBLE = 'dist/preamble.mp4';
const SFX = 'assets/audio/intro-analog-to-quantum.wav';
const MAIN = 'dist/mcps-intro-with-voice.mp4';
const OUT = 'dist/mcps-intro-final.mp4';

for (const f of [PREAMBLE, SFX, MAIN]) {
  if (!existsSync(f)) {
    console.error(`Missing input: ${f}`);
    if (f === PREAMBLE) {
      console.error(
        'Export the "mcps-preamble" project from the editor (FFmpeg) and save it as dist/preamble.mp4.',
      );
    }
    process.exit(1);
  }
}

// Normalise both segments to identical params, then concatenate (one re-encode).
const filter = [
  '[0:v]scale=1920:1080,fps=60,format=yuv420p,setsar=1[v0]',
  '[1:a]aformat=sample_rates=48000:channel_layouts=stereo[a0]',
  '[2:v]scale=1920:1080,fps=60,format=yuv420p,setsar=1[v1]',
  '[2:a]aformat=sample_rates=48000:channel_layouts=stereo[a1]',
  '[v0][a0][v1][a1]concat=n=2:v=1:a=1[v][a]',
].join(';');

execFileSync(
  'ffmpeg',
  [
    '-y',
    '-i', PREAMBLE, // 0: preamble video (audio ignored)
    '-i', SFX,      // 1: preamble audio (the braam SFX)
    '-i', MAIN,     // 2: narrated video + its voiceover
    '-filter_complex', filter,
    '-map', '[v]',
    '-map', '[a]',
    '-c:v', 'libx264',
    '-crf', '18',
    '-preset', 'medium',
    // Force constant frame rate + a clean timescale across the join, otherwise
    // some players desync/mute after the preamble->video seam.
    '-r', '60',
    '-fps_mode', 'cfr',
    '-video_track_timescale', '90000',
    '-c:a', 'aac',
    '-b:a', '192k',
    '-movflags', '+faststart',
    OUT,
  ],
  { stdio: 'inherit' },
);

console.log(`\nWrote ${OUT}`);
