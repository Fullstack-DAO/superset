export default function EchartsTimeseriesBar(props: EchartsTimeseriesChartProps) {
  const { height, width, echartOptions, setDataMask, labelMap, groupby, selectedValues } =
    props;

  if (!echartOptions) {
    return null;
  }

  return (
    <Echart
      height={height}
      width={width}
      echartOptions={echartOptions}
      eventHandlers={eventHandlers}
      selectedValues={selectedValues}
    />
  );
}

export function barTransformProps(chartProps: TimeseriesChartProps) {
  if (!chartProps.queriesData || !chartProps.queriesData[0]?.data) {
    return {
      height: chartProps.height,
      width: chartProps.width,
      echartOptions: {
        title: {
          text: 'No Data',
          left: 'center',
          top: 'center',
        },
      },
    };
  }

  const transformedProps = transformProps(chartProps);
  const { echartOptions } = transformedProps;
  
  return {
    ...transformedProps,
    echartOptions: {
      ...echartOptions,
    },
  };
} 