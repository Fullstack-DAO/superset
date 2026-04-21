declare module 'react-split-pane' {
  import * as React from 'react';

  export interface SplitPaneProps {
    allowResize?: boolean;
    children?: React.ReactNode;
    className?: string;
    defaultSize?: number | string;
    maxSize?: number | string;
    minSize?: number;
    onChange?: (newSize: number) => void;
    onDragFinished?: (newSize: number) => void;
    pane1Style?: React.CSSProperties;
    pane2Style?: React.CSSProperties;
    paneStyle?: React.CSSProperties;
    primary?: 'first' | 'second';
    resizerStyle?: React.CSSProperties;
    size?: number | string;
    split?: 'vertical' | 'horizontal';
    step?: number;
    style?: React.CSSProperties;
  }

  export default class SplitPane extends React.Component<SplitPaneProps> {}
}