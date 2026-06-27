import {makeProject} from '@motion-canvas/core';

import mcpsIntro from './scenes/mcps-intro?scene';

export default makeProject({
  name: 'mcps-intro-silent',
  scenes: [mcpsIntro],
  audio: './assets/audio/voiceover.wav',
});
