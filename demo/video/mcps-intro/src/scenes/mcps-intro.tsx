import { Layout, Line, makeScene2D, Node, Rect, Txt } from '@motion-canvas/2d';
import { all, createRef, waitFor, waitUntil } from '@motion-canvas/core';
import { Arrow } from '../components/Arrow';
import { AttackerOverlay } from '../components/AttackerOverlay';
import { EvidenceChip } from '../components/EvidenceChip';
import { KmsBox } from '../components/KmsBox';
import { LabeledBox } from '../components/LabeledBox';
import { Packet } from '../components/Packet';
import { StatusMarker } from '../components/StatusMarker';
import { TerminalLines } from '../components/TerminalLines';
import { theme } from '../theme';

function SceneHeader({ kicker, title, y = -430 }: any) {
  return (
    <Layout
      topLeft={[-900, y]}
      width={1200}
      layout
      direction={'column'}
      gap={12}
      alignItems={'start'}
    >
      <Txt
        text={kicker}
        fill={theme.cyan}
        fontFamily={'Inter, Arial, sans-serif'}
        fontSize={26}
        fontWeight={800}
      />
      <Txt
        text={title}
        fill={theme.ink}
        fontFamily={'Inter, Arial, sans-serif'}
        fontSize={56}
        fontWeight={850}
      />
    </Layout>
  );
}

function BottomCaption({ text }: any) {
  return (
    <Txt
      text={text}
      x={0}
      y={415}
      fill={theme.ink}
      fontFamily={'Inter, Arial, sans-serif'}
      fontSize={46}
      fontWeight={800}
    />
  );
}

function MainFlow({ mcps = true, boundary = false, y = 0 }: any) {
  const names = mcps
    ? ['Host / Agent', 'MCP-S', 'MCP Server', 'Tool']
    : ['Host', 'MCP Client', 'MCP Server', 'Tools'];
  const tones = mcps
    ? ['blue', 'green', 'neutral', 'neutral']
    : ['blue', 'neutral', 'neutral', 'neutral'];

  return (
    <Node y={y}>
      <LabeledBox label={names[0]} tone={tones[0]} x={-620} />
      <LabeledBox label={names[1]} tone={tones[1]} x={-210} />
      <LabeledBox label={names[2]} tone={tones[2]} x={210} />
      <LabeledBox label={names[3]} tone={tones[3]} x={620} />
      <Arrow from={[-488, 0]} to={[-342, 0]} color={theme.blue} />
      <Arrow from={[-78, 0]} to={[78, 0]} color={mcps ? theme.green : theme.blue} />
      <Arrow from={[342, 0]} to={[488, 0]} color={theme.blue} />
      {boundary ? (
        <Node>
          <Line
            points={[[0, -225], [0, 225]]}
            stroke={theme.red}
            lineWidth={3}
            lineDash={[16, 13]}
          />
          <Txt
            text={'call boundary'}
            x={0}
            y={-265}
            fill={theme.red}
            fontFamily={'Inter, Arial, sans-serif'}
            fontSize={28}
            fontWeight={800}
          />
        </Node>
      ) : null}
    </Node>
  );
}

function ToolCloud({ compact = false }: any) {
  return (
    <Node>
      <LabeledBox
        label={'AI assistant'}
        sublabel={'host + agent'}
        tone={'blue'}
        width={330}
        height={132}
        x={0}
        y={compact ? -90 : -120}
      />
      <LabeledBox label={'GitHub'} tone={'neutral'} x={-560} y={-220} />
      <LabeledBox label={'Database'} tone={'neutral'} x={560} y={-220} />
      <LabeledBox label={'Internal docs'} tone={'neutral'} width={300} x={-610} y={155} />
      <LabeledBox label={'Calendar'} tone={'neutral'} x={0} y={250} />
      <LabeledBox label={'Payment API'} tone={'neutral'} width={300} x={610} y={155} />
      <Arrow from={[-170, -145]} to={[-430, -205]} color={theme.blue} />
      <Arrow from={[170, -145]} to={[430, -205]} color={theme.blue} />
      <Arrow from={[-170, -75]} to={[-455, 135]} color={theme.blue} />
      <Arrow from={[0, -54]} to={[0, 180]} color={theme.blue} />
      <Arrow from={[170, -75]} to={[455, 135]} color={theme.blue} />
    </Node>
  );
}

function TangledLines() {
  return (
    <Node>
      <LabeledBox label={'Host'} tone={'blue'} width={220} x={-720} y={-140} />
      <LabeledBox label={'Agent'} tone={'blue'} width={220} x={-720} y={145} />
      <LabeledBox label={'GitHub'} width={210} x={500} y={-250} />
      <LabeledBox label={'DB'} width={210} x={700} y={-70} />
      <LabeledBox label={'Docs'} width={210} x={470} y={115} />
      <LabeledBox label={'Payments'} width={260} x={690} y={285} />
      <Line points={[[-607, -176], [120, -245], [390, -250]]} stroke={theme.faint} lineWidth={3} />
      <Line points={[[-607, -140], [80, -15], [590, -70]]} stroke={theme.faint} lineWidth={3} />
      <Line points={[[-607, 130], [-30, 55], [362, 115]]} stroke={theme.faint} lineWidth={3} />
      <Line points={[[-607, 165], [100, 250], [557, 285]]} stroke={theme.faint} lineWidth={3} />
      <Line
        points={[[-604, -109], [-135, 210], [554, 285]]}
        stroke={theme.red}
        lineWidth={3}
        lineDash={[12, 10]}
      />
    </Node>
  );
}

export default makeScene2D(function* (view) {
  view.fill(theme.bg);

  const scene1 = createRef<Node>();
  const scene1Tools = createRef<Node>();
  const scene1Flow = createRef<Node>();
  const scene2 = createRef<Node>();
  const tangled = createRef<Node>();
  const collapsed = createRef<Node>();
  const scene3 = createRef<Node>();
  const scene4Risk = createRef<Node>();
  const scene4Secure = createRef<Node>();
  const scene5 = createRef<Node>();
  const scene6 = createRef<Node>();
  const scene7 = createRef<Node>();

  const paymentPacket = createRef<Node>();
  const replayPacket = createRef<Node>();
  const securedPacket = createRef<Node>();
  const rejectedPacket = createRef<Node>();
  const evidenceGroup = createRef<Node>();
  const requestPacket = createRef<Node>();
  const responsePacket = createRef<Node>();
  const kmsSignature = createRef<Node>();

  view.add(
    <Node>
      <Node ref={scene1} opacity={0}>
        <SceneHeader kicker={'0:00'} title={'What MCP gives us'} />
        <Node ref={scene1Tools}>
          <ToolCloud />
        </Node>
        <Node ref={scene1Flow} opacity={0} y={-24}>
          <MainFlow mcps={false} />
        </Node>
        <BottomCaption text={'MCP = standard connections for AI tools'} />
      </Node>

      <Node ref={scene2} opacity={0}>
        <SceneHeader kicker={'0:10'} title={'Why developers like it'} />
        <Node ref={tangled}>
          <Txt
            text={'custom integrations'}
            x={-635}
            y={-330}
            fill={theme.muted}
            fontFamily={'Inter, Arial, sans-serif'}
            fontSize={28}
            fontWeight={800}
          />
          <TangledLines />
        </Node>
        <Node ref={collapsed} opacity={0} y={-40}>
          <MainFlow mcps={false} />
        </Node>
        <BottomCaption text={'Less glue. More reusable integrations.'} />
      </Node>

      <Node ref={scene3} opacity={0}>
        <SceneHeader kicker={'0:22'} title={'The security boundary'} />
        <MainFlow mcps={false} boundary y={-30} />
        <Layout x={0} y={250} layout gap={16} alignItems={'center'}>
          <StatusMarker label={'Identity'} tone={'neutral'} width={190} />
          <StatusMarker label={'Integrity'} tone={'neutral'} width={200} />
          <StatusMarker label={'Freshness'} tone={'neutral'} width={210} />
          <StatusMarker label={'Replay'} tone={'red'} width={170} />
          <StatusMarker label={'Response binding'} tone={'neutral'} width={295} />
        </Layout>
        <BottomCaption text={'The call boundary becomes a security boundary.'} />
      </Node>

      <Node ref={scene4Risk} opacity={0}>
        <SceneHeader kicker={'0:38'} title={'Concrete risk'} />
        <Node y={-150}>
          <LabeledBox label={'Agent'} tone={'blue'} x={-650} />
          <LabeledBox label={'MCP Server'} tone={'neutral'} x={0} />
          <LabeledBox label={'Payment API'} tone={'neutral'} width={300} x={650} />
          <Arrow from={[-520, 0]} to={[-155, 0]} color={theme.blue} />
          <Arrow from={[155, 0]} to={[500, 0]} color={theme.blue} />
          <Packet ref={paymentPacket} label={'pay #1042'} tone={'blue'} x={-430} y={-95} />
          <Packet
            ref={replayPacket}
            label={'pay #1042'}
            tone={'red'}
            x={-120}
            y={150}
            opacity={0}
          />
          <Arrow
            from={[-160, 150]}
            to={[500, 150]}
            color={theme.red}
            dashed
            label={'replay / tamper'}
          />
          <AttackerOverlay x={115} y={245} label={'duplicate or modified call'} crossed={false} />
        </Node>
        <Layout x={550} y={255} layout direction={'column'} gap={16} alignItems={'start'}>
          <StatusMarker label={'payment #1042 created'} tone={'green'} width={350} />
          <StatusMarker label={'duplicate payment created'} tone={'red'} width={405} />
          <StatusMarker label={'amount changed'} tone={'red'} width={295} />
        </Layout>
        <BottomCaption text={'One trusted action should not become two bad ones.'} />
      </Node>

      <Node ref={scene4Secure} opacity={0}>
        <SceneHeader kicker={'0:47'} title={'Same action, secured path'} />
        <Node y={-150}>
          <MainFlow mcps y={0} />
          <Packet ref={securedPacket} label={'pay #1042 + evidence'} tone={'cyan'} x={-610} y={-95} width={300} />
          <Packet ref={rejectedPacket} label={'replay'} tone={'red'} x={-60} y={150} opacity={0} />
          <Arrow from={[-170, 150]} to={[220, 150]} color={theme.red} dashed label={'replay'} />
          <AttackerOverlay x={240} y={245} label={'rejected'} />
        </Node>
        <Layout x={650} y={255} layout direction={'column'} gap={16} alignItems={'start'}>
          <StatusMarker label={'fresh request accepted'} tone={'green'} width={370} />
          <StatusMarker label={'duplicate rejected'} tone={'red'} width={330} />
        </Layout>
        <BottomCaption text={'One trusted action should not become two bad ones.'} />
      </Node>

      <Node ref={scene5} opacity={0}>
        <SceneHeader kicker={'0:55'} title={'Enter MCP-S'} />
        <Node y={-150}>
          <MainFlow mcps y={0} />
          <Rect
            x={0}
            y={0}
            width={620}
            height={185}
            radius={8}
            stroke={theme.green}
            lineWidth={3}
            lineDash={[14, 12]}
          />
          <Packet ref={requestPacket} label={'request'} tone={'blue'} x={-620} y={105} />
          <Packet ref={responsePacket} label={'response'} tone={'purple'} x={620} y={195} opacity={0} />
          <Node ref={evidenceGroup} y={150} opacity={0}>
            <Layout x={0} y={125} layout gap={16} alignItems={'center'}>
              <EvidenceChip label={'sig'} tone={'cyan'} />
              <EvidenceChip label={'nonce'} tone={'cyan'} />
              <EvidenceChip label={'exp'} tone={'cyan'} />
              <EvidenceChip label={'authz'} tone={'purple'} />
              <EvidenceChip label={'req_hash'} tone={'purple'} />
              <EvidenceChip label={'resp_hash'} tone={'purple'} />
            </Layout>
            <Layout x={0} y={255} layout gap={24} alignItems={'center'}>
              <StatusMarker label={'identity bound'} tone={'green'} width={270} />
              <StatusMarker label={'fresh call'} tone={'green'} width={220} />
              <StatusMarker label={'response matched'} tone={'green'} width={310} />
            </Layout>
          </Node>
        </Node>
        <BottomCaption text={'MCP-S = verifiable runtime evidence for MCP'} />
      </Node>

      <Node ref={scene6} opacity={0}>
        <SceneHeader kicker={'1:14'} title={'Enterprise key custody'} />
        <KmsBox x={-450} y={-30} />
        <LabeledBox
          label={'MCP-S'}
          sublabel={'verifier + signer'}
          tone={'green'}
          width={330}
          height={140}
          x={300}
          y={-30}
        />
        <Arrow from={[-240, -70]} to={[120, -70]} color={theme.gold} label={'sign request'} />
        <Arrow from={[120, 10]} to={[-240, 10]} color={theme.gold} label={'signature only'} />
        <Packet ref={kmsSignature} label={'sig'} tone={'gold'} x={-210} y={125} width={120} />
        <StatusMarker label={'private key not exported'} tone={'gold'} width={390} x={-450} y={245} />
        <EvidenceChip label={'sig'} tone={'gold'} x={300} y={245} />
        <BottomCaption text={'Enterprise key custody: sign without exporting keys'} />
      </Node>

      <Node ref={scene7} opacity={0}>
        <SceneHeader kicker={'1:25'} title={'Payoff'} />
        <TerminalLines
          x={0}
          y={-85}
          lines={[
            { text: 'valid request accepted', tone: 'green' },
            { text: 'tampered request rejected', tone: 'red' },
            { text: 'replay rejected', tone: 'red' },
            { text: 'bad response binding rejected', tone: 'red' },
          ]}
        />
        <Txt
          text={'Try MCP-S'}
          x={0}
          y={230}
          fill={theme.ink}
          fontFamily={'Inter, Arial, sans-serif'}
          fontSize={64}
          fontWeight={900}
        />
        <Txt
          text={'github.com/matssun/mcps'}
          x={0}
          y={310}
          fill={theme.cyan}
          fontFamily={'JetBrains Mono, Menlo, monospace'}
          fontSize={36}
          fontWeight={800}
        />
      </Node>
    </Node>,
  );

  // Timing is anchored to the generated voiceover via waitUntil() time events.
  // Targets live in mcps-intro.meta and were measured from assets/audio/voiceover.wav
  // (whisper word timestamps). Each section holds until its narration boundary, so
  // animation drift never accumulates. Re-measure and re-set the events if the
  // voiceover is regenerated with a different duration/pacing.

  // VO ~0:00: MCP gives agents a standard way to connect to external tools.
  yield* scene1().opacity(1, 0.5);
  yield* waitFor(3.8);
  yield* all(scene1Tools().opacity(0.12, 1.0), scene1Flow().opacity(1, 1.0));
  yield* waitUntil('s1-out');
  yield* scene1().opacity(0, 0.5);

  // VO ~0:12: Developers get less one-off glue and more reusable tool integrations.
  yield* scene2().opacity(1, 0.5);
  yield* waitFor(4.5);
  yield* all(tangled().opacity(0.08, 1.0), collapsed().opacity(1, 1.0));
  yield* waitUntil('s2-out');
  yield* scene2().opacity(0, 0.5);

  // VO ~0:23: Once the call crosses that boundary, security properties have to be explicit.
  yield* scene3().opacity(1, 0.5);
  yield* waitUntil('s3-out');
  yield* scene3().opacity(0, 0.5);

  // VO ~0:34: "Take a payment request. The agent sends pay invoice 1042."
  yield* scene4Risk().opacity(1, 0.5);
  yield* paymentPacket().x(500, 2.0);
  // Pause A: let the legitimate payment land before the attack is described.
  yield* waitUntil('s4-replay');
  // VO ~0:40: "If that call can be copied, replayed or changed, one trusted
  // action can become two bad ones." — the replay/duplicate is the attack.
  yield* all(replayPacket().opacity(1, 0.4), replayPacket().x(500, 2.2));
  // Hold on the attack through "two bad ones"; the defense plays during Pause B.
  yield* waitUntil('s4-secure');
  // Pause B (no narration): show the secured path answering the attack.
  yield* all(scene4Risk().opacity(0, 0.4), scene4Secure().opacity(1, 0.4));
  yield* securedPacket().x(610, 2.4);
  yield* all(rejectedPacket().opacity(1, 0.35), rejectedPacket().x(170, 1.5));
  // Beat after the rejection lands, then hand off to MCP-S.
  yield* waitUntil('s4-out');
  yield* scene4Secure().opacity(0, 0.5);

  // VO ~0:45: MCP-S wraps the MCP path with signatures, nonces, expiry, authz, and hashes.
  yield* scene5().opacity(1, 0.5);
  yield* requestPacket().x(0, 2.0);
  yield* all(evidenceGroup().opacity(1, 0.8), requestPacket().x(620, 2.0));
  yield* responsePacket().opacity(1, 0.35);
  yield* responsePacket().x(-620, 2.4);
  yield* waitUntil('s5-out');
  yield* scene5().opacity(0, 0.5);

  // VO ~1:05: Enterprise deployments can keep private keys inside managed KMS custody.
  yield* scene6().opacity(1, 0.5);
  yield* kmsSignature().x(300, 2.0);
  yield* waitUntil('s6-out');
  yield* scene6().opacity(0, 0.5);

  // VO ~1:18: The result is concrete runtime evidence developers can test and automate.
  yield* scene7().opacity(1, 0.5);
  yield* waitUntil('end');
});
