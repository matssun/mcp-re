import {Rect, Txt} from '@motion-canvas/2d';
import {theme} from '../theme';

type Tone = 'neutral' | 'green' | 'gold' | 'red' | 'cyan' | 'purple';

const toneMap = {
  neutral: [theme.neutralFill, theme.neutral],
  green: [theme.greenFill, theme.green],
  gold: [theme.goldFill, theme.gold],
  red: [theme.redFill, theme.red],
  cyan: [theme.cyanFill, theme.cyan],
  purple: [theme.purpleFill, theme.purple],
};

export interface EvidenceChipProps {
  label: string;
  tone?: Tone;
  [key: string]: any;
}

export function EvidenceChip({label, tone = 'neutral', ...props}: EvidenceChipProps) {
  const [fill, stroke] = toneMap[tone];

  return (
    <Rect
      width={150}
      height={50}
      radius={25}
      fill={fill}
      stroke={stroke}
      lineWidth={2}
      layout
      alignItems={'center'}
      justifyContent={'center'}
      {...props}
    >
      <Txt
        text={label}
        fill={stroke}
        fontFamily={'JetBrains Mono, Menlo, monospace'}
        fontSize={24}
        fontWeight={700}
      />
    </Rect>
  );
}
