import {defineConfig} from 'vite';
import motionCanvasPackage from '@motion-canvas/vite-plugin';
import ffmpegPackage from '@motion-canvas/ffmpeg';

const motionCanvas =
  typeof motionCanvasPackage === 'function'
    ? motionCanvasPackage
    : (motionCanvasPackage as any).default;

const ffmpeg =
  typeof ffmpegPackage === 'function'
    ? ffmpegPackage
    : (ffmpegPackage as any).default;

export default defineConfig({
  plugins: [
    motionCanvas({
      project: ['./src/project.ts', './src/preamble.ts'],
      output: './dist',
    }),
    ffmpeg(),
  ],
  build: {
    outDir: 'dist/build',
  },
});
