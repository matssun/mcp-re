import { blur, Layout, makeScene2D, Rect, Txt } from '@motion-canvas/2d';
import { all, createRef, waitFor, waitUntil } from '@motion-canvas/core';
import { theme } from '../theme';

/**
 * 5-second intro preamble — the "new kid on the block" pattern interrupt.
 *
 * Tone arc: materialize (something new emerging) -> deadpan aside (the joke)
 * -> confident reveal (authority). Synced to assets/audio/intro-analog-to-quantum.wav:
 * data-click bed under lines 1-2, then the braam SNAP lands exactly on the
 * "MCP-S" reveal (time event 'braam' = 3.0s); its warm tail carries the
 * subtitle, fading to silence/black at 5.0s so we walk into the narrated video.
 *
 * No motion or styling beyond the script: dark bg, clean type, deliberate + calm.
 */
export default makeScene2D(function* (view) {
  view.fill(theme.bg);

  const line1 = createRef<Txt>();
  const line2 = createRef<Txt>();
  const mcps = createRef<Txt>();
  const sub = createRef<Txt>();
  const l1Blur = blur(6);

  const SUB_REST = 92;

  view.add(
    <Layout>
      {/* Lines 1 & 2: the tease and the deadpan aside */}
      <Txt
        ref={line1}
        text={"There's a new kid on the protocol block."}
        y={-36}
        fill={theme.ink}
        fontFamily={'Inter, Arial, sans-serif'}
        fontSize={66}
        fontWeight={600}
        opacity={0}
        scale={0.92}
        filters={[l1Blur]}
      />
      <Txt
        ref={line2}
        text={'No, not the 90s boy band.'}
        y={48}
        fill={'#A0A0A0'}
        fontFamily={'Inter, Arial, sans-serif'}
        fontSize={38}
        fontStyle={'italic'}
        fontWeight={400}
        opacity={0}
      />

      {/* Line 3: the authoritative reveal (hits on the braam) */}
      <Txt
        ref={mcps}
        text={'MCP-S'}
        y={-44}
        fill={theme.ink}
        fontFamily={'Inter, Arial, sans-serif'}
        fontSize={156}
        fontWeight={800}
        letterSpacing={6}
        opacity={0}
        scale={1.04}
      />
      <Txt
        ref={sub}
        text={'Verifiable runtime evidence for MCP calls.'}
        y={SUB_REST + 12}
        fill={theme.muted}
        fontFamily={'Inter, Arial, sans-serif'}
        fontSize={42}
        fontWeight={400}
        opacity={0}
      />
    </Layout>,
  );

  // Let the data-clicks establish, then Line 1 softly materializes into place.
  yield* waitFor(0.3);
  yield* all(
    line1().opacity(1, 0.8),
    line1().scale(1, 0.8),
    l1Blur.value(0, 0.8),
  );

  // Line 2: deadpan, minimal — quick fade, no motion. Let the joke land.
  yield* waitUntil('l2');
  yield* line2().opacity(1, 0.3);

  // Clear the room just before the reveal.
  yield* waitUntil('clear');
  yield* all(line1().opacity(0, 0.3), line2().opacity(0, 0.3));

  // SNAP/BRAAM at 3.0s: MCP-S enters confident and stable (fade + tiny settle).
  yield* waitUntil('braam');
  yield* all(mcps().opacity(1, 0.5), mcps().scale(1, 0.5));

  // Subtitle fades up just under it — classic, authoritative.
  yield* waitUntil('sub');
  yield* all(sub().opacity(1, 0.5), sub().y(SUB_REST, 0.5));

  // Settle, then fade to black into the narrated video as the braam tail dies.
  yield* waitUntil('out');
  yield* all(mcps().opacity(0, 0.4), sub().opacity(0, 0.4));
  yield* waitUntil('end');
});
