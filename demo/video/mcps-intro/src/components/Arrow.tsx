import {Line, Node, Txt} from '@motion-canvas/2d';
import {theme} from '../theme';

type Point = [number, number];

export interface ArrowProps {
  from: Point;
  to: Point;
  label?: string;
  color?: string;
  dashed?: boolean;
  lineWidth?: number;
  [key: string]: any;
}

export function Arrow({
  from,
  to,
  label,
  color = theme.neutral,
  dashed = false,
  lineWidth = 3,
  ...props
}: ArrowProps) {
  const midX = (from[0] + to[0]) / 2;
  const midY = (from[1] + to[1]) / 2;

  return (
    <Node {...props}>
      <Line
        points={[from, to]}
        stroke={color}
        lineWidth={lineWidth}
        endArrow
        arrowSize={13}
        lineDash={dashed ? [18, 12] : []}
      />
      {label ? (
        <Txt
          text={label}
          x={midX}
          y={midY - 30}
          fill={color}
          fontFamily={'Inter, Arial, sans-serif'}
          fontSize={24}
          fontWeight={650}
        />
      ) : null}
    </Node>
  );
}
