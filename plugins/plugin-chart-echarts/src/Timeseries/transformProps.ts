import { TimeseriesChartProps, TimeseriesDataRecord } from '@superset-ui/core';
import { EChartsCoreOption } from 'echarts';

export interface TransformedProps {
  width: number;
  height: number;
  echartOptions: EChartsCoreOption;
}

export default function transformProps(chartProps: TimeseriesChartProps): TransformedProps {
  const {
    width,
    height,
    filterState,
    legendState,
    formData,
    hooks,
    queriesData,
    datasource,
    theme,
    inContextMenu,
    emitCrossFilters,
  } = chartProps;

  // 添加完整的数据检查
  if (!queriesData?.[0]?.data || !Array.isArray(queriesData[0].data)) {
    return {
      width,
      height,
      formData,
      echartOptions: {
        title: {
          text: 'No Data',
          left: 'center',
          top: 'center',
        },
      },
      labelMap: {},
      groupby: [],
      selectedValues: {},
      emitCrossFilters,
      xAxis: {
        label: '',
        type: 'time',
      },
    };
  }

  let focusedSeries: string | null = null;

  const {
    verboseMap = {},
    columnFormats = {},
    currencyFormats = {},
  } = datasource || {};
  
  const [queryData] = queriesData;
  const data = queryData?.data || [];
  const label_map = queryData?.label_map || {};

  const dataTypes = getColtypesMapping(queryData);
  const annotationData = getAnnotationData(chartProps);

  const {
    area,
    annotationLayers,
    colorScheme,
    contributionMode,
    forecastEnabled,
    groupby = [],
    legendOrientation,
    legendType,
    legendMargin,
    logAxis,
    markerEnabled,
    markerSize,
    metrics = [],
  } = { ...DEFAULT_FORM_DATA, ...formData };

  // 检查 metrics 数组
  if (!metrics || !Array.isArray(metrics) || metrics.length === 0) {
    return {
      width,
      height,
      formData,
      echartOptions: {
        title: {
          text: 'No Metrics Selected',
          left: 'center',
          top: 'center',
        },
      },
      labelMap: {},
      groupby: [],
      selectedValues: {},
      emitCrossFilters,
      xAxis: {
        label: '',
        type: 'time',
      },
    };
  }

  // 处理数据转换
  const series = data.map((item: TimeseriesDataRecord) => {
    return {
      name: metrics[0]?.label || '',
      type: 'line',
      data: [item.x, item.y],
    };
  });

  // 构建 echarts 配置
  const echartOptions: EChartsCoreOption = {
    grid: {
      left: '3%',
      right: '4%',
      bottom: '3%',
      containLabel: true,
    },
    xAxis: {
      type: 'time',
    },
    yAxis: {
      type: 'value',
    },
    series,
    tooltip: {
      trigger: 'axis',
    },
  };

  return {
    width,
    height,
    echartOptions,
  };
} 