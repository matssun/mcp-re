import {Layout, Rect, Txt} from '@motion-canvas/2d';
import {theme} from '../theme';

export interface TerminalLine {
  text: string;
  tone?: 'green' | 'red' | 'neutral';
}

export interface TerminalLinesProps {
  lines: TerminalLine[];
  [key: string]: any;
}

const colors = {
  green: '#86efac',
  red: '#fca5a5',
  neutral: '#cbd5e1',
};

export function TerminalLines({lines, ...props}: TerminalLinesProps) {
  return (
    <Rect
      width={780}
      height={320}
      radius={8}
      fill={theme.terminal}
      stroke={theme.faint}
      lineWidth={2}
      padding={30}
      layout
      direction={'column'}
      alignItems={'start'}
      gap={18}
      {...props}
    >
      {lines.map((line, index) => (
        <Layout key={index} layout gap={18} alignItems={'center'}>
          <Txt
            text={'$'}
            fill={'#64748b'}
            fontFamily={'JetBrains Mono, Menlo, monospace'}
            fontSize={28}
            fontWeight={700}
          />
          <Txt
            text={line.text}
            fill={colors[line.tone ?? 'neutral']}
            fontFamily={'JetBrains Mono, Menlo, monospace'}
            fontSize={28}
            fontWeight={650}
          />
        </Layout>
      ))}
    </Rect>
  );
}
