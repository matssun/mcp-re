import {Rect, Txt} from '@motion-canvas/2d';
import {theme} from '../theme';

type Tone = 'blue' | 'green' | 'red' | 'cyan' | 'purple' | 'gold';

const toneMap = {
  blue: [theme.blueFill, theme.blue],
  green: [theme.greenFill, theme.green],
  red: [theme.redFill, theme.red],
  cyan: [theme.cyanFill, theme.cyan],
  purple: [theme.purpleFill, theme.purple],
  gold: [theme.goldFill, theme.gold],
};

export interface PacketProps {
  label: string;
  tone?: Tone;
  width?: number;
  [key: string]: any;
}

export function Packet({label, tone = 'blue', width = 210, ...props}: PacketProps) {
  const [fill, stroke] = toneMap[tone];

  return (
    <Rect
      width={width}
      height={54}
      radius={8}
      fill={fill}
      stroke={stroke}
      lineWidth={2}
      padding={[0, 18]}
      layout
      alignItems={'center'}
      justifyContent={'center'}
      {...props}
    >
      <Txt
        text={label}
        fill={theme.ink}
        fontFamily={'JetBrains Mono, Menlo, monospace'}
        fontSize={22}
        fontWeight={750}
      />
    </Rect>
  );
}
