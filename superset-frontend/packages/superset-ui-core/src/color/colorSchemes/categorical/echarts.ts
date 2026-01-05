/*
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

import CategoricalScheme from '../../CategoricalScheme';

const schemes = [
  {
    id: 'echarts4Colors',
    label: 'ECharts v4.x Colors',
    colors: [
      '#70CD87',
      '#647CFC',
      '#2D99FF',
      '#FFC825',
      '#935DFB',
      '#3BA272',
      '#FC8452',
      '#9A60B4',
      '#EA7CCC',
      '#546570',
      '#c4ccd3',
    ],
  },
  {
    id: 'echarts5Colors',
    label: 'ECharts v5.x Colors',
    colors: [
      '#70CD87',
      '#647CFC',
      '#2D99FF',
      '#FFC825',
      '#935DFB',
      '#3BA272',
      '#FC8452',
      '#9A60B4',
      '#EA7CCC',
    ],
  },
].map(s => new CategoricalScheme(s));

export default schemes;
