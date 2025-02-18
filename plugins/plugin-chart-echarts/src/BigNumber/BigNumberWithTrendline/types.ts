import { QueryFormData, ChartProps } from '@superset-ui/core';

export interface BigNumberTrendlineFormData extends QueryFormData {
  colorPicker?: {
    value?: {
      r: number;
      g: number;
      b: number;
      a: number;
    };
  };
  headerFontSize?: string | number;
  subheaderFontSize?: string | number;
}

export interface BigNumberTrendlineChartProps extends ChartProps {
  formData: BigNumberTrendlineFormData;
} 