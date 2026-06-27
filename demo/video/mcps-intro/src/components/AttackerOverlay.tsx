import {Line, Node, Rect, Txt} from '@motion-canvas/2d';
import {theme} from '../theme';

export interface AttackerOverlayProps {
  label?: string;
  crossed?: boolean;
  [key: string]: any;
}

export function AttackerOverlay({
  label = 'copied or modified call',
  crossed = true,
  ...props
}: AttackerOverlayProps) {
  return (
    <Node {...props}>
      <Rect
        width={380}
        height={112}
        radius={8}
        fill={theme.redFill}
        stroke={theme.red}
        lineWidth={2}
        lineDash={[14, 10]}
        layout
        alignItems={'center'}
        justifyContent={'center'}
      >
        <Txt
          text={label}
          fill={theme.red}
          fontFamily={'Inter, Arial, sans-serif'}
          fontSize={27}
          fontWeight={800}
        />
      </Rect>
      {crossed && (
        <>
          <Line
            points={[[-180, -70], [180, 70]]}
            stroke={theme.red}
            lineWidth={4}
            lineDash={[18, 12]}
          />
          <Line
            points={[[180, -70], [-180, 70]]}
            stroke={theme.red}
            lineWidth={4}
            lineDash={[18, 12]}
          />
        </>
      )}
    </Node>
  );
}
