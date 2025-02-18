import { BigNumberTrendlineChartProps } from './types';

export default function transformProps(chartProps: BigNumberTrendlineChartProps) {
  const {
    width,
    height,
    formData,
    queriesData,
  } = chartProps;

  // 直接设置默认颜色值
  let r = 0, g = 0, b = 0, a = 1;

  try {
    // 安全地访问嵌套属性
    if (formData?.colorPicker?.value) {
      r = formData.colorPicker.value.r ?? 0;
      g = formData.colorPicker.value.g ?? 0;
      b = formData.colorPicker.value.b ?? 0;
      a = formData.colorPicker.value.a ?? 1;
    }
  } catch (error) {
    console.warn('Error accessing color values:', error);
  }

  // 安全地获取其他属性
  const headerFontSize = formData?.headerFontSize ?? 'auto';
  const subheaderFontSize = formData?.subheaderFontSize ?? 'auto';

  // 安全地获取数据值
  let value = 0;
  try {
    const queryData = queriesData?.[0] ?? {};
    const data = queryData?.data ?? [];
    value = data[0]?.value ?? 0;
  } catch (error) {
    console.warn('Error accessing data value:', error);
  }

  return {
    width,
    height,
    value,
    color: `rgba(${r}, ${g}, ${b}, ${a})`,
    headerFontSize,
    subheaderFontSize,
  };
} 