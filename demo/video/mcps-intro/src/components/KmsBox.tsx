import {Layout, Rect, Txt} from '@motion-canvas/2d';
import {theme} from '../theme';

export interface KmsBoxProps {
  [key: string]: any;
}

export function KmsBox(props: KmsBoxProps) {
  return (
    <Rect
      width={420}
      height={220}
      radius={8}
      fill={theme.goldFill}
      stroke={theme.gold}
      lineWidth={3}
      padding={28}
      layout
      direction={'column'}
      alignItems={'center'}
      justifyContent={'center'}
      gap={16}
      {...props}
    >
      <Txt
        text={'Google Cloud KMS'}
        fill={theme.ink}
        fontFamily={'Inter, Arial, sans-serif'}
        fontSize={34}
        fontWeight={800}
      />
      <Layout layout direction={'column'} alignItems={'center'} gap={6}>
        <Txt
          text={'private key stays inside'}
          fill={theme.gold}
          fontFamily={'Inter, Arial, sans-serif'}
          fontSize={24}
          fontWeight={700}
        />
        <Txt
          text={'signatures leave KMS'}
          fill={theme.muted}
          fontFamily={'Inter, Arial, sans-serif'}
          fontSize={22}
          fontWeight={600}
        />
      </Layout>
    </Rect>
  );
}
