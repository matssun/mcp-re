import {Rect, Txt} from '@motion-canvas/2d';
import {theme} from '../theme';

type Tone = 'neutral' | 'green' | 'red' | 'gold';

const toneMap = {
  neutral: [theme.neutralFill, theme.neutral],
  green: [theme.greenFill, theme.green],
  red: [theme.redFill, theme.red],
  gold: [theme.goldFill, theme.gold],
};

export interface StatusMarkerProps {
  label: string;
  tone?: Tone;
  width?: number;
  [key: string]: any;
}

export function StatusMarker({
  label,
  tone = 'neutral',
  width = 260,
  ...props
}: StatusMarkerProps) {
  const [fill, stroke] = toneMap[tone];

  return (
    <Rect
      width={width}
      height={58}
      radius={8}
      fill={fill}
      stroke={stroke}
      lineWidth={2}
      padding={[0, 20]}
      layout
      alignItems={'center'}
      gap={14}
      {...props}
    >
      <Txt
        text={tone === 'red' ? 'X' : tone === 'neutral' ? '-' : '✓'}
        fill={stroke}
        fontFamily={'Inter, Arial, sans-serif'}
        fontSize={25}
        fontWeight={900}
      />
      <Txt
        text={label}
        fill={theme.ink}
        fontFamily={'Inter, Arial, sans-serif'}
        fontSize={24}
        fontWeight={650}
      />
    </Rect>
  );
}
