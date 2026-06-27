import {Layout, Rect, Txt} from '@motion-canvas/2d';
import {theme} from '../theme';

type Tone = 'neutral' | 'blue' | 'green' | 'red' | 'gold' | 'cyan' | 'purple';

const toneMap = {
  neutral: [theme.neutralFill, theme.neutral],
  blue: [theme.blueFill, theme.blue],
  green: [theme.greenFill, theme.green],
  red: [theme.redFill, theme.red],
  gold: [theme.goldFill, theme.gold],
  cyan: [theme.cyanFill, theme.cyan],
  purple: [theme.purpleFill, theme.purple],
};

export interface LabeledBoxProps {
  label: string;
  sublabel?: string;
  tone?: Tone;
  width?: number;
  height?: number;
  fontSize?: number;
  [key: string]: any;
}

export function LabeledBox({
  label,
  sublabel,
  tone = 'neutral',
  width = 260,
  height = 112,
  fontSize = 34,
  ...props
}: LabeledBoxProps) {
  const [fill, stroke] = toneMap[tone];

  return (
    <Rect
      width={width}
      height={height}
      radius={8}
      fill={fill}
      stroke={stroke}
      lineWidth={2}
      padding={22}
      layout
      direction={'column'}
      alignItems={'center'}
      justifyContent={'center'}
      gap={8}
      {...props}
    >
      <Txt
        text={label}
        fill={theme.ink}
        fontFamily={'Inter, Arial, sans-serif'}
        fontSize={fontSize}
        fontWeight={700}
      />
      {sublabel ? (
        <Txt
          text={sublabel}
          fill={theme.muted}
          fontFamily={'Inter, Arial, sans-serif'}
          fontSize={21}
          fontWeight={500}
        />
      ) : null}
    </Rect>
  );
}
