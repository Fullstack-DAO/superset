/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
/* eslint-disable camelcase */
import { invert } from 'lodash';
import {
  AnnotationLayer,
  AxisType,
  buildCustomFormatters,
  CategoricalColorNamespace,
  CurrencyFormatter,
  ensureIsArray,
  GenericDataType,
  getCustomFormatter,
  getMetricLabel,
  getNumberFormatter,
  getXAxisLabel,
  isDefined,
  isEventAnnotationLayer,
  isFormulaAnnotationLayer,
  isIntervalAnnotationLayer,
  isPhysicalColumn,
  isTimeseriesAnnotationLayer,
  t,
  SupersetTheme,
} from '@superset-ui/core';
import {
  extractExtraMetrics,
  getOriginalSeries,
  isDerivedSeries,
} from '@superset-ui/chart-controls';
import { EChartsCoreOption, SeriesOption } from 'echarts';
import { ZRLineType } from 'echarts/types/src/util/types';
import { TreeSeriesOption } from 'echarts/charts';
import {
  EchartsTimeseriesChartProps,
  EchartsTimeseriesFormData,
  OrientationType,
  TimeseriesChartTransformedProps,
} from './types';
import { DEFAULT_FORM_DATA } from './constants';
import {
  ForecastSeriesEnum,
  ForecastValue,
  Refs,
  DeepPartial,
} from '../types';
import { parseAxisBound } from '../utils/controls';
import {
  calculateLowerLogTick,
  dedupSeries,
  extractDataTotalValues,
  extractSeries,
  extractShowValueIndexes,
  getAxisType,
  getColtypesMapping,
  getLegendProps,
  getMinAndMaxFromBounds,
} from '../utils/series';
import {
  extractAnnotationLabels,
  getAnnotationData,
} from '../utils/annotation';
import {
  extractForecastSeriesContext,
  extractForecastSeriesContexts,
  extractForecastValuesFromTooltipParams,
  formatForecastTooltipSeries,
  rebaseForecastDatum,
} from '../utils/forecast';
import { convertInteger } from '../utils/convertInteger';
import { defaultGrid, defaultYAxis } from '../defaults';
import {
  getBaselineSeriesForStream,
  getPadding,
  transformEventAnnotation,
  transformFormulaAnnotation,
  transformIntervalAnnotation,
  transformSeries,
  transformTimeseriesAnnotation,
} from './transformers';
import {
  StackControlsValue,
  TIMEGRAIN_TO_TIMESTAMP,
  TIMESERIES_CONSTANTS,
} from '../constants';
import { getDefaultTooltip } from '../utils/tooltip';
import {
  getTooltipTimeFormatter,
  getXAxisFormatter,
  getYAxisFormatter,
} from '../utils/formatters';

type LabelMap = {
  [key: string]: string[];
};

interface TimeseriesChartDataResponse {
  data: any[];
  label_map?: {
    [key: string]: string[];
  };
}

interface DatasourceType {
  verboseMap?: Record<string, string>;
  columnFormats?: Record<string, string>;
  currencyFormats?: Record<string, any>;
}

export default function transformProps(
  chartProps: EchartsTimeseriesChartProps,
): TimeseriesChartTransformedProps {
  // 添加防御性检查
  if (!chartProps?.queriesData?.[0]?.data) {
    const defaultProps = {
      width: chartProps?.width || 800,
      height: chartProps?.height || 600,
      formData: chartProps?.formData || {},
      emitCrossFilters: false,
    };

    return {
      width: defaultProps.width,
      height: defaultProps.height,
      echartOptions: {
        grid: { ...defaultGrid },
        series: [],
        xAxis: {
          type: AxisType.category,
          data: []
        },
        yAxis: { type: AxisType.value },
      },
      formData: defaultProps.formData,
      groupby: [],
      labelMap: {},
      selectedValues: {},
      setDataMask: () => {},
      setControlValue: () => {},
      legendData: [],
      onContextMenu: () => {},
      onLegendStateChanged: () => {},
      onFocusedSeries: () => {},
      xValueFormatter: String,
      xAxis: {
        label: '',
        type: AxisType.category,
      },
      refs: {},
      coltypeMapping: {},
      emitCrossFilters: defaultProps.emitCrossFilters,
    };
  }

  // 只保留一次解构，移除重复的解构
  const {
    width,
    height,
    formData,
    queriesData,
    filterState = {},
    legendState = {},
    hooks = {},
    datasource = {} as DatasourceType,
    theme = {} as SupersetTheme,
    inContextMenu = false,
    emitCrossFilters = false,
  } = chartProps;

  let focusedSeries: string | null = null;

  // 解构 datasource
  const {
    verboseMap = {},
    columnFormats = {},
    currencyFormats = {},
  } = datasource;

  const [queryData] = queriesData;
  const rawData = queryData as unknown as TimeseriesChartDataResponse;
  const { data = [], label_map = {} } = rawData;

  const dataTypes = getColtypesMapping(queryData);
  const annotationData = getAnnotationData(chartProps);

  const {
    area,
    annotationLayers,
    colorScheme,
    contributionMode,
    forecastEnabled,
    groupby,
    legendOrientation,
    legendType,
    legendMargin,
    logAxis,
    markerEnabled,
    markerSize,
    metrics,
    minorSplitLine,
    minorTicks,
    onlyTotal,
    opacity,
    orientation,
    percentageThreshold,
    richTooltip,
    seriesType,
    showLegend,
    showValue,
    sliceId,
    sortSeriesType,
    sortSeriesAscending,
    timeGrainSqla,
    timeCompare,
    stack,
    tooltipTimeFormat,
    tooltipSortByMetric,
    truncateXAxis,
    truncateYAxis,
    xAxis: xAxisOrig,
    xAxisBounds,
    xAxisForceCategorical,
    xAxisLabelRotation,
    xAxisSortSeries,
    xAxisSortSeriesAscending,
    xAxisTimeFormat,
    xAxisTitle,
    xAxisTitleMargin,
    yAxisBounds,
    yAxisFormat,
    currencyFormat,
    yAxisTitle,
    yAxisTitleMargin,
    yAxisTitlePosition,
    zoomable,
  }: EchartsTimeseriesFormData = { ...DEFAULT_FORM_DATA, ...formData };
  const refs: Refs = {};

  const labelMap = Object.entries(label_map || {}).reduce<LabelMap>((acc, entry) => {
    const [key, value] = entry;
    if (!Array.isArray(value)) {
      return { ...acc, [key]: [] };
    }

    if (
      value.length > groupby.length &&
      Array.isArray(timeCompare) &&
      timeCompare.includes(value[0])
    ) {
      const newEntry = [...value];
      newEntry.shift();
      return { ...acc, [key]: newEntry };
    }

    return { ...acc, [key]: value };
  }, {});

  const colorScale = CategoricalColorNamespace.getScale(colorScheme as string);
  const rebasedData = rebaseForecastDatum(data, verboseMap);
  let xAxisLabel = getXAxisLabel(chartProps.rawFormData) as string;
  if (
    isPhysicalColumn(chartProps.rawFormData?.x_axis) &&
    isDefined(verboseMap[xAxisLabel])
  ) {
    xAxisLabel = verboseMap[xAxisLabel];
  }
  const isHorizontal = orientation === OrientationType.horizontal;
  const { totalStackedValues, thresholdValues } = extractDataTotalValues(
    rebasedData,
    {
      stack,
      percentageThreshold,
      xAxisCol: xAxisLabel,
      legendState,
    },
  );
  const extraMetricLabels = extractExtraMetrics(chartProps.rawFormData).map(
    getMetricLabel,
  );

  // 确保 groupby 和 metrics 都有值且是数组
  const groupbyArray = Array.isArray(groupby) ? groupby : [];
  const metricsArray = Array.isArray(metrics) ? metrics : [];

  // 修改 isMultiSeries 的定义
  const isMultiSeries = groupbyArray.length > 0 || metricsArray.length > 1;

  const [rawSeriesTemp, sortedTotalValuesTemp, minPositiveValueTemp] = extractSeries(
    rebasedData || [],
    {
      fillNeighborValue: stack && !forecastEnabled ? 0 : undefined,
      xAxis: xAxisLabel || '',
      extraMetricLabels: extraMetricLabels || [],
      stack,
      totalStackedValues: totalStackedValues || [],
      isHorizontal,
      sortSeriesType,
      sortSeriesAscending,
      xAxisSortSeries: isMultiSeries ? xAxisSortSeries : undefined,
      xAxisSortSeriesAscending: isMultiSeries
        ? xAxisSortSeriesAscending
        : undefined,
    },
  ) || [[], [], undefined];

  const rawSeries = Array.isArray(rawSeriesTemp) ? rawSeriesTemp : [];
  const sortedTotalValues = Array.isArray(sortedTotalValuesTemp) ? sortedTotalValuesTemp : [];
  const minPositiveValue = minPositiveValueTemp;

  const showValueIndexes = extractShowValueIndexes(rawSeries || [], {
    stack,
    onlyTotal,
    isHorizontal,
    legendState: legendState || {},
  }) || [];

  const seriesContexts = extractForecastSeriesContexts(
    (rawSeries || []).map(series => String(series?.name || '')),
  ) || {};

  const isAreaExpand = stack === StackControlsValue.Expand;
  const xAxisDataType = dataTypes?.[xAxisLabel] ?? dataTypes?.[xAxisOrig];

  const xAxisType = getAxisType(stack, xAxisForceCategorical, xAxisDataType);
  const series: DeepPartial<SeriesOption | TreeSeriesOption>[] = [];

  const forcePercentFormatter = Boolean(contributionMode || isAreaExpand);
  const percentFormatter = getNumberFormatter(',.0%');
  const defaultFormatter = currencyFormat?.symbol
    ? new CurrencyFormatter({ d3Format: yAxisFormat, currency: currencyFormat })
    : getNumberFormatter(yAxisFormat);
  const customFormatters = buildCustomFormatters(
    metrics,
    currencyFormats,
    columnFormats,
    yAxisFormat,
    currencyFormat,
  );

  const array = ensureIsArray(chartProps.rawFormData?.time_compare);
  const inverted = invert(verboseMap);

  (rawSeries || []).forEach(entry => {
    if (!entry || typeof entry !== 'object') {
      return;
    }

    const lineStyle = isDerivedSeries(entry, chartProps.rawFormData)
      ? { type: 'dashed' as ZRLineType }
      : {};

    const entryName = String(entry.name || '');
    const seriesName = inverted[entryName] || entryName;
    const colorScaleKey = getOriginalSeries(seriesName, array);

    if (!entry.data || !Array.isArray(entry.data)) {
      return;
    }

    const transformedSeries = transformSeries(
      entry,
      colorScale,
      colorScaleKey,
      {
        area,
        filterState,
        seriesContexts,
        markerEnabled,
        markerSize,
        areaOpacity: opacity,
        seriesType,
        legendState,
        stack,
        formatter: forcePercentFormatter
          ? percentFormatter
          : getCustomFormatter(
              customFormatters,
              metrics,
              labelMap[seriesName]?.[0] ?? '',
            ) ?? defaultFormatter,
        showValue,
        onlyTotal,
        totalStackedValues: sortedTotalValues,
        showValueIndexes,
        thresholdValues,
        richTooltip,
        sliceId,
        isHorizontal,
        lineStyle,
      },
    );

    if (transformedSeries) {
      if (stack === StackControlsValue.Stream) {
        const safeData = Array.isArray(transformedSeries.data)
          ? transformedSeries.data.map((row: any) => {
              if (Array.isArray(row) && row.length >= 2) {
                return [row[0], row[1] ?? 0];
              }
              return [null, 0];
            })
          : [];

        series.push({
          ...transformedSeries,
          data: safeData,
        } as DeepPartial<SeriesOption>);
      } else {
        series.push(transformedSeries as DeepPartial<SeriesOption>);
      }
    }
  });

  if (!series.length) {
    series.push({
      type: 'bar',
      data: [],
    });
  }

  if (stack === StackControlsValue.Stream && series.length > 0) {
    try {
      const baselineSeries = getBaselineSeriesForStream(
        series.map(entry => Array.isArray(entry.data) ? entry.data : []) as [string | number, number][][],
        seriesType,
      );
      if (baselineSeries) {
        series.unshift(baselineSeries);
      }
    } catch (e) {
      console.warn('Failed to create baseline series for stream chart:', e);
    }
  }
  const selectedValues = (filterState.selectedValues || []).reduce(
    (acc: Record<string, number>, selectedValue: string) => {
      const index = series.findIndex(({ name }) => name === selectedValue);
      return {
        ...acc,
        [index]: selectedValue,
      };
    },
    {},
  );

  annotationLayers
    .filter((layer: AnnotationLayer) => layer.show)
    .forEach((layer: AnnotationLayer) => {
      if (isFormulaAnnotationLayer(layer))
        series.push(
          transformFormulaAnnotation(
            layer,
            data,
            xAxisLabel,
            xAxisType,
            colorScale,
            sliceId,
          ),
        );
      else if (isIntervalAnnotationLayer(layer)) {
        series.push(
          ...transformIntervalAnnotation(
            layer,
            data,
            annotationData,
            colorScale,
            theme as SupersetTheme,
            sliceId,
          ),
        );
      } else if (isEventAnnotationLayer(layer)) {
        series.push(
          ...transformEventAnnotation(
            layer,
            data,
            annotationData,
            colorScale,
            theme as SupersetTheme,
            sliceId,
          ),
        );
      } else if (isTimeseriesAnnotationLayer(layer)) {
        series.push(
          ...transformTimeseriesAnnotation(
            layer,
            markerSize,
            data,
            annotationData,
            colorScale,
            sliceId,
          ),
        );
      }
    });

  // axis bounds need to be parsed to replace incompatible values with undefined
  const [xAxisMin, xAxisMax] = (xAxisBounds || []).map(parseAxisBound);
  let [yAxisMin, yAxisMax] = (yAxisBounds || []).map(parseAxisBound);

  // default to 0-100% range when doing row-level contribution chart
  if ((contributionMode === 'row' || isAreaExpand) && stack) {
    if (yAxisMin === undefined) yAxisMin = 0;
    if (yAxisMax === undefined) yAxisMax = 1;
  } else if (
    logAxis &&
    yAxisMin === undefined &&
    minPositiveValue !== undefined
  ) {
    yAxisMin = calculateLowerLogTick(minPositiveValue);
  }

  const tooltipFormatter =
    xAxisDataType === GenericDataType.TEMPORAL
      ? getTooltipTimeFormatter(tooltipTimeFormat)
      : String;
  const xAxisFormatter =
    xAxisDataType === GenericDataType.TEMPORAL
      ? getXAxisFormatter(xAxisTimeFormat)
      : String;

  const {
    setDataMask = () => {},
    setControlValue = () => {},
    onContextMenu,
    onLegendStateChanged,
  } = hooks;

  const addYAxisLabelOffset = !!yAxisTitle;
  const addXAxisLabelOffset = !!xAxisTitle;
  const padding = getPadding(
    showLegend,
    legendOrientation,
    addYAxisLabelOffset,
    zoomable,
    legendMargin,
    addXAxisLabelOffset,
    yAxisTitlePosition,
    convertInteger(yAxisTitleMargin),
    convertInteger(xAxisTitleMargin),
  );

  const legendData = rawSeries
    .filter(
      entry =>
        extractForecastSeriesContext(entry.name || '').type ===
        ForecastSeriesEnum.Observation,
    )
    .map(entry => entry.name || '')
    .concat(extractAnnotationLabels(annotationLayers, annotationData));

  let xAxis: any = {
    type: xAxisType,
    name: xAxisTitle,
    nameGap: convertInteger(xAxisTitleMargin),
    nameLocation: 'middle',
    axisLabel: {
      hideOverlap: true,
      formatter: xAxisFormatter,
      rotate: xAxisLabelRotation,
    },
    minorTick: { show: minorTicks },
    minInterval:
      xAxisType === AxisType.time && timeGrainSqla && timeGrainSqla in TIMEGRAIN_TO_TIMESTAMP
        ? TIMEGRAIN_TO_TIMESTAMP[timeGrainSqla as keyof typeof TIMEGRAIN_TO_TIMESTAMP]
        : 0,
    ...getMinAndMaxFromBounds(
      xAxisType,
      truncateXAxis,
      xAxisMin,
      xAxisMax,
      seriesType,
    ),
  };

  let yAxis: any = {
    ...defaultYAxis,
    type: logAxis ? AxisType.log : AxisType.value,
    min: yAxisMin,
    max: yAxisMax,
    minorTick: { show: minorTicks },
    minorSplitLine: { show: minorSplitLine },
    axisLabel: {
      formatter: getYAxisFormatter(
        metrics,
        forcePercentFormatter,
        customFormatters,
        defaultFormatter,
      ),
    },
    scale: truncateYAxis,
    name: yAxisTitle,
    nameGap: convertInteger(yAxisTitleMargin),
    nameLocation: yAxisTitlePosition === 'Left' ? 'middle' : 'end',
  };

  if (isHorizontal) {
    [xAxis, yAxis] = [yAxis, xAxis];
    [padding.bottom, padding.left] = [padding.left, padding.bottom];
    yAxis.inverse = true;
  }

  const echartOptions: EChartsCoreOption = {
    useUTC: true,
    grid: {
      ...defaultGrid,
      ...padding,
    },
    xAxis,
    yAxis,
    tooltip: {
      ...getDefaultTooltip(refs),
      show: !inContextMenu,
      trigger: richTooltip ? 'axis' : 'item',
      formatter: (params: any) => {
        const [xIndex, yIndex] = isHorizontal ? [1, 0] : [0, 1];
        const xValue: number = richTooltip
          ? params[0].value[xIndex]
          : params.value[xIndex];
        const forecastValue: any[] = richTooltip ? params : [params];

        if (richTooltip && tooltipSortByMetric) {
          forecastValue.sort((a, b) => b.data[yIndex] - a.data[yIndex]);
        }

        const rows: string[] = [];
        const forecastValues: Record<string, ForecastValue> =
          extractForecastValuesFromTooltipParams(forecastValue, isHorizontal);

        Object.keys(forecastValues).forEach(key => {
          const value = forecastValues[key];
          if (value.observation === 0 && stack) {
            return;
          }
          // if there are no dimensions, key is a verbose name of a metric,
          // otherwise it is a comma separated string where the first part is metric name
          const formatterKey =
            groupby.length === 0 ? inverted[key] : (labelMap[key]?.[0] ?? '');
          const content = formatForecastTooltipSeries({
            ...value,
            seriesName: key,
            formatter: forcePercentFormatter
              ? percentFormatter
              : getCustomFormatter(customFormatters, metrics, formatterKey) ??
                defaultFormatter,
          });
          const contentStyle =
            key === focusedSeries ? 'font-weight: 700' : 'opacity: 0.7';
          rows.push(`<span style="${contentStyle}">${content}</span>`);
        });
        if (stack) {
          rows.reverse();
        }
        rows.unshift(`${tooltipFormatter(xValue)}`);
        return rows.join('<br />');
      },
    },
    legend: {
      ...getLegendProps(
        legendType,
        legendOrientation,
        showLegend,
        theme as SupersetTheme,
        zoomable,
        legendState,
      ),
      data: legendData as string[],
    },
    series: dedupSeries(series as SeriesOption[]),
    toolbox: {
      show: zoomable,
      top: TIMESERIES_CONSTANTS.toolboxTop,
      right: TIMESERIES_CONSTANTS.toolboxRight,
      feature: {
        dataZoom: {
          yAxisIndex: false,
          title: {
            zoom: t('zoom area'),
            back: t('restore zoom'),
          },
        },
      },
    },
    dataZoom: zoomable
      ? [
          {
            type: 'slider',
            start: TIMESERIES_CONSTANTS.dataZoomStart,
            end: TIMESERIES_CONSTANTS.dataZoomEnd,
            bottom: TIMESERIES_CONSTANTS.zoomBottom,
          },
        ]
      : [],
  };

  const onFocusedSeries = (seriesName: string | null) => {
    focusedSeries = seriesName;
  };

  return {
    echartOptions,
    emitCrossFilters,
    formData,
    groupby,
    height,
    labelMap,
    selectedValues,
    setDataMask,
    setControlValue,
    width,
    legendData,
    onContextMenu,
    onLegendStateChanged,
    onFocusedSeries,
    xValueFormatter: tooltipFormatter,
    xAxis: {
      label: xAxisLabel,
      type: xAxisType,
    },
    refs,
    coltypeMapping: dataTypes,
  };
}
