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
import {
  AnnotationType,
  Behavior,
  hasGenericChartAxes,
  t,
  ChartDataResponseResult,
} from '@superset-ui/core';
import {
  EchartsTimeseriesChartProps,
  EchartsTimeseriesFormData,
  EchartsTimeseriesSeriesType,
} from '../../types';
import { EchartsChartPlugin } from '../../../types';
import buildQuery from '../../buildQuery';
import controlPanel from './controlPanel';
import transformProps from '../../transformProps';
import thumbnail from './images/thumbnail.png';
import example1 from './images/Bar1.png';
import example2 from './images/Bar2.png';
import example3 from './images/Bar3.png';

// 修改类型定义
interface ExtendedChartDataResponseResult extends ChartDataResponseResult {
  label_map?: Record<string, string[]>;
}

const barTransformProps = (chartProps: EchartsTimeseriesChartProps) => {
  // 添加类型安全检查
  const modifiedChartProps = {
    ...chartProps,
    queriesData: chartProps.queriesData?.map(queryData => {
      const typedQueryData = queryData as ExtendedChartDataResponseResult;
      return {
        ...typedQueryData,
        data: typedQueryData.data || [],
        label_map: typedQueryData.label_map || {},
        // 保持其他必需的 ChartDataResponseResult 属性
        annotation_data: typedQueryData.annotation_data,
        cache_key: typedQueryData.cache_key,
        cache_timeout: typedQueryData.cache_timeout,
        cached_dttm: typedQueryData.cached_dttm,
        error: typedQueryData.error,
        is_cached: typedQueryData.is_cached,
        query: typedQueryData.query,
        rowcount: typedQueryData.rowcount,
        stacktrace: typedQueryData.stacktrace,
        status: typedQueryData.status,
      };
    }) || [{
      data: [],
      label_map: {},
      annotation_data: null,
      cache_key: null,
      cache_timeout: null,
      cached_dttm: null,
      error: null,
      is_cached: false,
      query: '',
      rowcount: 0,
      stacktrace: null,
      status: 'success',
    }],
    formData: {
      ...chartProps.formData,
      seriesType: EchartsTimeseriesSeriesType.Bar,
    },
  };

  return transformProps(modifiedChartProps);
};

export default class EchartsTimeseriesBarChartPlugin extends EchartsChartPlugin<
  EchartsTimeseriesFormData,
  EchartsTimeseriesChartProps
> {
  constructor() {
    super({
      buildQuery,
      controlPanel,
      loadChart: () => import('../../EchartsTimeseries'),
      metadata: {
        behaviors: [
          Behavior.INTERACTIVE_CHART,
          Behavior.DRILL_TO_DETAIL,
          Behavior.DRILL_BY,
        ],
        category: t('Evolution'),
        credits: ['https://echarts.apache.org'],
        description: hasGenericChartAxes
          ? t('Bar Charts are used to show metrics as a series of bars.')
          : t(
              'Time-series Bar Charts are used to show the changes in a metric over time as a series of bars.',
            ),
        exampleGallery: [
          { url: example1 },
          { url: example2 },
          { url: example3 },
        ],
        supportedAnnotationTypes: [
          AnnotationType.Event,
          AnnotationType.Formula,
          AnnotationType.Interval,
          AnnotationType.Timeseries,
        ],
        name: hasGenericChartAxes ? t('Bar Chart') : t('Time-series Bar Chart'),
        tags: [
          t('ECharts'),
          t('Predictive'),
          t('Advanced-Analytics'),
          t('Aesthetic'),
          t('Time'),
          t('Transformable'),
          t('Stacked'),
          t('Vertical'),
          t('Bar'),
          t('Popular'),
        ],
        thumbnail,
      },
      transformProps: barTransformProps,
    });
  }
}
