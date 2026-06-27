import { makeProject } from '@motion-canvas/core';

import preamble from './scenes/preamble?scene';

export default makeProject({
  name: 'mcps-preamble',
  scenes: [preamble],
  audio: './assets/audio/intro-analog-to-quantum.wav',
});
