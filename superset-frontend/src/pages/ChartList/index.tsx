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
  ensureIsArray,
  isFeatureEnabled,
  FeatureFlag,
  getChartMetadataRegistry,
  JsonResponse,
  styled,
  SupersetClient,
  t,
} from '@superset-ui/core';
import React, {
  useState,
  useMemo,
  useCallback,
  useEffect,
  useRef,
} from 'react';
import rison from 'rison';
import { uniqBy } from 'lodash';
// import { useSelector } from 'react-redux';
import {
  createErrorHandler,
  handleChartDelete,
} from 'src/views/CRUD/utils';
import {
  useChartEditModal,
  useFavoriteStatus,
  useListViewResource,
} from 'src/views/CRUD/hooks';
import handleResourceExport from 'src/utils/export';
import ConfirmStatusChange from 'src/components/ConfirmStatusChange';
import { TagsList } from 'src/components/Tags';
import SubMenu, { SubMenuProps } from 'src/features/home/SubMenu';
import FaveStar from 'src/components/FaveStar';
import { Link, useHistory, useLocation } from 'react-router-dom';
import ListView, {
  Filter,
  FilterOperator,
  Filters,
  FilterValue,
  ListViewProps,
  SelectOption,
} from 'src/components/ListView';
import CrossLinks from 'src/components/ListView/CrossLinks';
import Loading from 'src/components/Loading';
import { dangerouslyGetItemDoNotUse } from 'src/utils/localStorageHelpers';
import withToasts from 'src/components/MessageToasts/withToasts';
import PropertiesModal from 'src/explore/components/PropertiesModal';
import ImportModelsModal from 'src/components/ImportModal/index';
import Chart, { ChartLinkedDashboard } from 'src/types/Chart';
import Tag from 'src/types/TagType';
import { Tooltip } from 'src/components/Tooltip';
import Icons from 'src/components/Icons';
import InfoTooltip from 'src/components/InfoTooltip';
import CertifiedBadge from 'src/components/CertifiedBadge';
import { GenericLink } from 'src/components/GenericLink/GenericLink';
// import { loadTags } from 'src/components/Tags/utils';
import FacePile from 'src/components/FacePile';
import ChartCard from 'src/features/charts/ChartCard';
// import { UserWithPermissionsAndRoles } from 'src/types/bootstrapTypes';
// import { findPermission } from 'src/utils/findPermission';
import { ModifiedInfo } from 'src/components/AuditInfo';
import { QueryObjectColumns } from 'src/views/CRUD/types';
import useBreakpoint from 'antd/lib/grid/hooks/useBreakpoint';
import { FetchDataConfig } from 'src/components/ListView/types';
import {
  CHART_FOLDER_QUERY_KEY,
  ChartFolder,
  emitChartFoldersUpdated,
  removeChartFromFolder,
} from 'src/features/charts/folders/api';
import useChartFolders from 'src/features/charts/folders/useChartFolders';

const ListViewContainer = styled.div`
  background-color: #FFFFFF;
  padding: ${({ theme }) => theme.gridUnit * 4}px;
  min-height: calc(100vh - 150px);
  margin: 0 16px 16px;
  border-radius: ${({ theme }) => theme.borderRadius}px;
`;

const FlexRowContainer = styled.div`
  align-items: center;
  display: flex;

  a {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    line-height: 1.2;
  }

  svg {
    margin-right: ${({ theme }) => theme.gridUnit}px;
  }
`;

const PAGE_SIZE = 25;
const PASSWORDS_NEEDED_MESSAGE = t(
  'The passwords for the databases below are needed in order to ' +
    'import them together with the charts. Please note that the ' +
    '"Secure Extra" and "Certificate" sections of ' +
    'the database configuration are not present in export files, and ' +
    'should be added manually after the import if they are needed.',
);
const CONFIRM_OVERWRITE_MESSAGE = t(
  'You are importing one or more charts that already exist. ' +
    'Overwriting might cause you to lose some of your work. Are you ' +
    'sure you want to overwrite?',
);

const registry = getChartMetadataRegistry();

const createFetchDatasets = async (
  filterValue = '',
  page: number,
  pageSize: number,
) => {
  // add filters if filterValue
  const filters = filterValue
    ? { filters: [{ col: 'table_name', opr: 'sw', value: filterValue }] }
    : {};
  const queryParams = rison.encode({
    columns: ['datasource_name', 'datasource_id'],
    keys: ['none'],
    order_column: 'table_name',
    order_direction: 'asc',
    page,
    page_size: pageSize,
    ...filters,
  });

  const { json = {} } = await SupersetClient.get({
    endpoint: `/api/v1/dataset/?q=${queryParams}`,
  });

  const datasets = json?.result?.map(
    ({ table_name: tableName, id }: { table_name: string; id: number }) => ({
      label: tableName,
      value: id,
    }),
  );

  return {
    data: uniqBy<SelectOption>(datasets, 'value'),
    totalCount: json?.count,
  };
};

const parseChartJsonField = (value: unknown) => {
  if (!value) {
    return undefined;
  }
  if (typeof value === 'object') {
    return value as Record<string, any>;
  }
  if (typeof value === 'string') {
    try {
      return JSON.parse(value) as Record<string, any>;
    } catch {
      return undefined;
    }
  }
  return undefined;
};

const parseDatasourceId = (value: unknown): number | undefined => {
  if (typeof value === 'number') {
    return value;
  }
  if (typeof value === 'string' && value.length > 0) {
    const [datasourceId] = value.split('__');
    const parsedId = Number(datasourceId);
    return Number.isNaN(parsedId) ? undefined : parsedId;
  }
  return undefined;
};

const getDatasourceIdFromChart = (chart: Record<string, any>): number | undefined => {
  const queryContext = parseChartJsonField(chart.query_context);
  const queryContextDatasourceId = parseDatasourceId(
    queryContext?.datasource?.id ?? queryContext?.form_data?.datasource,
  );

  if (queryContextDatasourceId) {
    return queryContextDatasourceId;
  }

  const directDatasourceId = chart.datasource_id ?? chart.datasource?.id;
  if (typeof directDatasourceId === 'number') {
    return directDatasourceId;
  }
  if (typeof directDatasourceId === 'string' && directDatasourceId.length > 0) {
    const parsedId = Number(directDatasourceId);
    return Number.isNaN(parsedId) ? undefined : parsedId;
  }

  const params = parseChartJsonField(chart.params);
  const datasourceValue = chart.form_data?.datasource ?? params?.datasource;

  return parseDatasourceId(datasourceValue);
};

const getChartDatasourceName = async (chart: Record<string, any>) => {
  const existingDatasourceName =
    chart.datasource_name_text ??
    chart.datasource?.datasource_name ??
    chart.datasource?.table_name ??
    chart.datasource_name;

  if (existingDatasourceName) {
    return existingDatasourceName;
  }

  const datasourceId = getDatasourceIdFromChart(chart);
  if (!datasourceId) {
    return '';
  }

  try {
    const { json } = await SupersetClient.get({
      endpoint: `/api/v1/dataset/${datasourceId}`,
    });
    return (
      json?.result?.name ??
      json?.result?.table_name ??
      json?.result?.datasource_name ??
      ''
    );
  } catch {
    return '';
  }
};

interface ChartListProps {
  addDangerToast: (msg: string) => void;
  addSuccessToast: (msg: string) => void;
  user: {
    userId: string | number;
    firstName: string;
    lastName: string;
  };
}

const StyledActions = styled.div`
  color: ${({ theme }) => theme.colors.grayscale.base};
`;

// 添加权限类型定义
type ChartPermissions = {
  can_write: boolean;
  can_export: boolean;
  can_delete: boolean;
  role: string;
};

type FolderChartsState = {
  loading: boolean;
  collection: Chart[];
  count: number;
  lastFetchDataConfig: FetchDataConfig | null;
};

function ChartList(props: ChartListProps) {
  const {
    addDangerToast,
    addSuccessToast,
    user: { userId },
  } = props;
  const screens = useBreakpoint();
  const history = useHistory();
  const location = useLocation();

  const {
    state: {
      loading,
      resourceCount: chartCount,
      resourceCollection: charts,
      bulkSelectEnabled,
    },
    setResourceCollection: setCharts,
    hasPerm,
    fetchData,
    toggleBulkSelect,
    refreshData,
    getResourcePermissions,
  } = useListViewResource<Chart>('chart', t('chart'), addDangerToast);
  const [folderState, setFolderState] = useState<FolderChartsState>({
    loading: false,
    collection: [],
    count: 0,
    lastFetchDataConfig: null,
  });
  const selectedFolderId = useMemo(
    () => new URLSearchParams(location.search).get(CHART_FOLDER_QUERY_KEY),
    [location.search],
  );
  const { chartFolders } = useChartFolders();
  const selectedFolder = useMemo<ChartFolder | null>(
    () => chartFolders.find(folder => folder.id === selectedFolderId) ?? null,
    [chartFolders, selectedFolderId],
  );
  const isFolderView = !!selectedFolder;
  const activeCharts = isFolderView ? folderState.collection : charts;
  const activeChartCount = isFolderView ? folderState.count : chartCount;
  const activeLoading = isFolderView ? folderState.loading : loading;
  const chartIds = useMemo(
    () =>
      isFolderView
        ? selectedFolder?.items.map(item => item.chartId) ?? []
        : charts.map(c => c.id),
    [charts, isFolderView, selectedFolder],
  );
  // const { roles } = useSelector<any, UserWithPermissionsAndRoles>(
  //   state => state.user,
  // );
  // const canReadTag = findPermission('can_read', 'Tag', roles);

  const [saveFavoriteStatus, favoriteStatus] = useFavoriteStatus(
    'chart',
    chartIds,
    addDangerToast,
  );
  const favoriteStatusRef = useRef(favoriteStatus);

  useEffect(() => {
    favoriteStatusRef.current = favoriteStatus;
  }, [favoriteStatus]);
  const {
    sliceCurrentlyEditing,
    handleChartUpdated,
    openChartEditModal,
    closeChartEditModal,
  } = useChartEditModal(setCharts, charts);

  const [importingChart, showImportModal] = useState<boolean>(false);
  const [passwordFields, setPasswordFields] = useState<string[]>([]);
  const [preparingExport, setPreparingExport] = useState<boolean>(false);
  const [sshTunnelPasswordFields, setSSHTunnelPasswordFields] = useState<
    string[]
  >([]);
  const [sshTunnelPrivateKeyFields, setSSHTunnelPrivateKeyFields] = useState<
    string[]
  >([]);
  const [
    sshTunnelPrivateKeyPasswordFields,
    setSSHTunnelPrivateKeyPasswordFields,
  ] = useState<string[]>([]);

  // TODO: Fix usage of localStorage keying on the user id
  const userSettings = dangerouslyGetItemDoNotUse(userId?.toString(), null) as {
    thumbnails: boolean;
  };

  const [chartPermissions, setChartPermissions] = useState<
    Record<number, ChartPermissions>
  >({});

  const fetchChartPermissions = useCallback(async () => {
    try {
      const response = await SupersetClient.get({
        endpoint: `/api/v1/chart/_info?q=(keys:!(permissions))`,
      });
      if (response?.json?.permissions) {
        setChartPermissions(response.json.permissions);
      }
    } catch (err) {
      console.error('Failed to fetch chart permissions:', err);
      addDangerToast(t('Failed to fetch chart permissions'));
    }
  }, [addDangerToast]);

  useEffect(() => {
    fetchChartPermissions();
  }, [fetchChartPermissions]);

  // const getChartPermissions = (chartId: number): ChartPermissions => {
  //   return chartPermissions[chartId] || {
  //     can_write: false,
  //     can_export: false,
  //     can_delete: false,
  //     role: 'viewer'
  //   };
  // };

  const openChartImportModal = () => {
    showImportModal(true);
  };

  const closeChartImportModal = () => {
    showImportModal(false);
  };

  const handleChartImport = () => {
    showImportModal(false);
    refreshData();
    addSuccessToast(t('Chart imported'));
  };

  // 添加全局权限状态
  const [globalPermissions, setGlobalPermissions] = useState<{
    can_write: boolean;
  }>({
    can_write: false,
  });

  // 修改 hasPerm 函数的使用
  const canCreate = globalPermissions.can_write; // 使用全局权限

  const getSelectBooleanValue = useCallback((value?: FilterValue['value']) => {
    if (typeof value === 'boolean') {
      return value;
    }

    if (
      value &&
      typeof value === 'object' &&
      'value' in value &&
      typeof value.value === 'boolean'
    ) {
      return value.value;
    }

    return undefined;
  }, []);

  const getSelectFilterValue = useCallback((value?: FilterValue['value']) => {
    if (
      value &&
      typeof value === 'object' &&
      !Array.isArray(value) &&
      'value' in value
    ) {
      return value.value;
    }

    return value;
  }, []);

  // 在组件加载时获取权限信息
  useEffect(() => {
    const fetchPermissions = async () => {
      try {
        const response = await SupersetClient.get({
          endpoint: `/api/v1/chart/_info`,
        });
        if (response?.json?.global_permissions) {
          setGlobalPermissions(response.json.global_permissions);
        }
      } catch (err) {
        console.error('Failed to fetch permissions:', err);
        addDangerToast(t('Failed to fetch permissions'));
      }
    };

    fetchPermissions();
  }, [addDangerToast]);

  const fetchFolderCharts = useCallback(
    async ({ pageIndex, pageSize, sortBy, filters }: FetchDataConfig) => {
      setFolderState(currentState => ({
        ...currentState,
        loading: true,
        lastFetchDataConfig: {
          pageIndex,
          pageSize,
          sortBy,
          filters,
        },
      }));

      if (!selectedFolder) {
        setFolderState({
          loading: false,
          collection: [],
          count: 0,
          lastFetchDataConfig: {
            pageIndex,
            pageSize,
            sortBy,
            filters,
          },
        });
        return;
      }

      const chartsInFolder = await Promise.all(
        selectedFolder.items.map(async item => {
          try {
            const { json } = await SupersetClient.get({
              endpoint: `/api/v1/chart/${item.chartId}`,
            });
            const chart = json?.result;

            if (!chart?.id) {
              return { chart: null, staleItemId: item.id };
            }

            const datasourceNameText = await getChartDatasourceName(chart);

            return {
              chart: {
                ...chart,
                cache_timeout: chart.cache_timeout ?? null,
                datasource_id: getDatasourceIdFromChart(chart),
                datasource_name_text: datasourceNameText,
                datasource_url: chart.datasource_url ?? chart.datasource?.url,
                dashboards: chart.dashboards || [],
                description: chart.description ?? null,
                form_data: chart.form_data || { viz_type: chart.viz_type || '' },
                is_managed_externally: !!chart.is_managed_externally,
                owners: chart.owners || [],
                slice_name: chart.slice_name || item.name,
                tags: chart.tags || [],
                url: chart.url || item.url,
              } as Chart,
              staleItemId: null,
            };
          } catch {
            return { chart: null, staleItemId: item.id };
          }
        }),
      );

      const staleItemIds = chartsInFolder
        .map(result => result.staleItemId)
        .filter(Boolean) as string[];

      if (staleItemIds.length) {
        await Promise.all(
          selectedFolder.items
            .filter(item => staleItemIds.includes(item.id))
            .map(item => removeChartFromFolder(selectedFolder.id, item.id)),
        );
        emitChartFoldersUpdated();
      }

      const collection = chartsInFolder
        .map(result => result.chart)
        .filter(Boolean) as Chart[];
      const nameFilter = filters.find(filter => filter.id === 'slice_name');
      const datasetFilter = filters.find(filter => filter.id === 'datasource_id');
      const dashboardFilter = filters.find(filter => filter.id === 'dashboards');
      const favoriteFilter = filters.find(
        filter => (filter.urlDisplay || filter.id) === 'favorite',
      );
      const searchValue =
        typeof nameFilter?.value === 'string'
          ? nameFilter.value.trim().toLowerCase()
          : '';
      const datasetValue = getSelectFilterValue(datasetFilter?.value);
      const dashboardValue = getSelectFilterValue(dashboardFilter?.value);
      const favoriteValue = getSelectBooleanValue(favoriteFilter?.value);
      const filteredCollection = collection.filter(chart => {
        const chartDatasourceId = (
          chart as Chart & { datasource_id?: number | string }
        ).datasource_id;
        const name = chart.slice_name?.toLowerCase() || '';
        const url = chart.url?.toLowerCase() || '';
        const matchesSearch =
          !searchValue || name.includes(searchValue) || url.includes(searchValue);
        const matchesDataset =
          datasetValue === undefined ||
          datasetValue === null ||
          String(chartDatasourceId) === String(datasetValue);
        const matchesDashboard =
          dashboardValue === undefined ||
          dashboardValue === null ||
          ensureIsArray(chart.dashboards).some(
            (dashboard: ChartLinkedDashboard) =>
              String(dashboard.id) === String(dashboardValue),
          );

        return matchesSearch && matchesDataset && matchesDashboard;
      });
      const visibilityFilteredCollection = filteredCollection.filter(chart =>
        typeof favoriteValue === 'boolean'
          ? Boolean(favoriteStatusRef.current[chart.id]) === favoriteValue
          : true,
      );
      const sortedCollection = [...visibilityFilteredCollection].sort((a, b) => {
        const sortKey = sortBy[0]?.id || 'changed_on_delta_humanized';
        const sortDesc = sortBy[0]?.desc ?? true;
        const valueA = a[sortKey as keyof Chart];
        const valueB = b[sortKey as keyof Chart];

        return sortDesc
          ? String(valueB ?? '').localeCompare(String(valueA ?? ''))
          : String(valueA ?? '').localeCompare(String(valueB ?? ''));
      });

      const startIndex = pageIndex * pageSize;
      const pagedCollection = sortedCollection.slice(
        startIndex,
        startIndex + pageSize,
      );

      setFolderState({
        loading: false,
        collection: pagedCollection,
        count: sortedCollection.length,
        lastFetchDataConfig: {
          pageIndex,
          pageSize,
          sortBy,
          filters,
        },
      });
    },
    [
      favoriteStatusRef,
      getSelectBooleanValue,
      getSelectFilterValue,
      selectedFolder,
    ],
  );

  const activeFetchData = isFolderView ? fetchFolderCharts : fetchData;
  const activeRefreshData = useCallback(
    (provideConfig?: FetchDataConfig | null) => {
      if (isFolderView) {
        if (folderState.lastFetchDataConfig) {
          return fetchFolderCharts(folderState.lastFetchDataConfig);
        }
        if (provideConfig) {
          return fetchFolderCharts(provideConfig);
        }
        return null;
      }

      return refreshData(provideConfig || undefined);
    },
    [fetchFolderCharts, folderState.lastFetchDataConfig, isFolderView, refreshData],
  );

  const canEdit = hasPerm('can_write');
  const canDelete = hasPerm('can_write');
  const canExport =
    hasPerm('can_export') && isFeatureEnabled(FeatureFlag.VERSIONED_EXPORT);
  const initialSort = [{ id: 'changed_on_delta_humanized', desc: true }];
  const handleBulkChartExport = (chartsToExport: Chart[]) => {
    const ids = chartsToExport.map(({ id }) => id);
    handleResourceExport('chart', ids, () => {
      setPreparingExport(false);
    });
    setPreparingExport(true);
  };

  function handleBulkChartDelete(chartsToDelete: Chart[]) {
    SupersetClient.delete({
      endpoint: `/api/v1/chart/?q=${rison.encode(
        chartsToDelete.map(({ id }) => id),
      )}`,
    }).then(
      ({ json = {} }) => {
        refreshData();
        addSuccessToast(json.message);
      },
      createErrorHandler(errMsg =>
        addDangerToast(
          t('There was an issue deleting the selected charts: %s', errMsg),
        ),
      ),
    );
  }
  const fetchDashboards = async (
    filterValue = '',
    page: number,
    pageSize: number,
  ) => {
    // add filters if filterValue
    const filters = filterValue
      ? {
          filters: [
            {
              col: 'dashboard_title',
              opr: FilterOperator.startsWith,
              value: filterValue,
            },
          ],
        }
      : {};
    const queryParams = rison.encode({
      columns: ['dashboard_title', 'id'],
      keys: ['none'],
      order_column: 'dashboard_title',
      order_direction: 'asc',
      page,
      page_size: pageSize,
      ...filters,
    });
    const response: void | JsonResponse = await SupersetClient.get({
      endpoint: `/api/v1/dashboard/?q=${queryParams}`,
    }).catch(() =>
      addDangerToast(t('An error occurred while fetching dashboards')),
    );
    const dashboards = response?.json?.result?.map(
      ({
        dashboard_title: dashboardTitle,
        id,
      }: {
        dashboard_title: string;
        id: number;
      }) => ({
        label: dashboardTitle,
        value: id,
      }),
    );
    return {
      data: uniqBy<SelectOption>(dashboards, 'value'),
      totalCount: response?.json?.count,
    };
  };

  const columns = useMemo(
    () => [
      {
        Cell: ({
          row: {
            original: { id },
          },
        }: any) =>
          userId && (
            <FaveStar
              itemId={id}
              saveFaveStar={saveFavoriteStatus}
              isStarred={favoriteStatus[id]}
            />
          ),
        Header: '',
        id: 'id',
        disableSortBy: true,
        size: 'xs',
        hidden: !userId,
      },
      {
        Cell: ({
          row: {
            original: {
              url,
              slice_name: sliceName,
              certified_by: certifiedBy,
              certification_details: certificationDetails,
              description,
            },
          },
        }: any) => (
          <FlexRowContainer>
            <Link to={url} data-test={`${sliceName}-list-chart-title`}>
              {certifiedBy && (
                <>
                  <CertifiedBadge
                    certifiedBy={certifiedBy}
                    details={certificationDetails}
                  />{' '}
                </>
              )}
              {sliceName}
            </Link>
            {description && <InfoTooltip tooltip={description} />}
          </FlexRowContainer>
        ),
        Header: t('Name'),
        accessor: 'slice_name',
      },
      {
        Cell: ({
          row: {
            original: { viz_type: vizType },
          },
        }: any) => registry.get(vizType)?.name || vizType,
        Header: t('Type'),
        accessor: 'viz_type',
        size: 'xxl',
      },
      {
        Cell: ({
          row: {
            original: {
              datasource_name_text: dsNameTxt,
              datasource_url: dsUrl,
            },
          },
        }: any) => <GenericLink to={dsUrl}>{dsNameTxt}</GenericLink>,
        Header: t('Dataset'),
        accessor: 'datasource_id',
        disableSortBy: true,
        size: 'xl',
      },
      {
        Cell: ({
          row: {
            original: { dashboards },
          },
        }: any) => (
          <CrossLinks
            crossLinks={ensureIsArray(dashboards).map(
              (d: ChartLinkedDashboard) => ({
                title: d.dashboard_title,
                id: d.id,
              }),
            )}
          />
        ),
        Header: t('Dashboards added to'),
        accessor: 'dashboards',
        disableSortBy: true,
        size: 'xxl',
        hidden: true,
      },
      {
        Cell: ({
          row: {
            original: { tags = [] },
          },
        }: any) => (
          // Only show custom type tags
          <TagsList
            tags={tags.filter((tag: Tag) =>
              tag.type
                ? tag.type === 1 || tag.type === 'TagTypes.custom'
                : true,
            )}
            maxTags={3}
          />
        ),
        Header: t('Tags'),
        accessor: 'tags',
        disableSortBy: true,
        hidden: !isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM),
      },
      {
        Cell: ({
          row: {
            original: { owners = [] },
          },
        }: any) => <FacePile users={owners} />,
        Header: t('Owners'),
        accessor: 'owners',
        disableSortBy: true,
        size: 'xl',
      },
      {
        Cell: ({
          row: {
            original: {
              changed_on_delta_humanized: changedOn,
              changed_by: changedBy,
            },
          },
        }: any) => <ModifiedInfo date={changedOn} user={changedBy} />,
        Header: t('Last modified'),
        accessor: 'last_saved_at',
        size: 'xl',
      },
      {
        Cell: ({ row: { original } }: any) => {
          const handleDelete = () =>
            handleChartDelete(
              original,
              addSuccessToast,
              addDangerToast,
              activeRefreshData,
            );
          const openEditModal = () => openChartEditModal(original);
          const handleExport = () => handleBulkChartExport([original]);

          // 使用 hook 提供的权限检查函数
          const permissions = getResourcePermissions(original.id);

          // 如果没有读权限，不显示任何操作按钮
          if (!permissions.can_read) {
            return null;
          }

          return (
            <StyledActions className="actions">
              {permissions.can_delete && (
                <ConfirmStatusChange
                  title={t('Please confirm')}
                  description={
                    <>
                      {t('Are you sure you want to delete')}{' '}
                      <b>{original.slice_name}</b>?
                    </>
                  }
                  onConfirm={handleDelete}
                >
                  {confirmDelete => (
                    <Tooltip
                      id="delete-action-tooltip"
                      title={t('Delete')}
                      placement="bottom"
                    >
                      <span
                        data-test="trash"
                        role="button"
                        tabIndex={0}
                        className="action-button"
                        onClick={confirmDelete}
                      >
                        <Icons.Trash />
                      </span>
                    </Tooltip>
                  )}
                </ConfirmStatusChange>
              )}
              {permissions.can_export && (
                <Tooltip
                  id="export-action-tooltip"
                  title={t('Export')}
                  placement="bottom"
                >
                  <span
                    role="button"
                    tabIndex={0}
                    className="action-button"
                    onClick={handleExport}
                  >
                    <Icons.Share />
                  </span>
                </Tooltip>
              )}
              {permissions.can_write && (
                <Tooltip
                  id="edit-action-tooltip"
                  title={t('Edit')}
                  placement="bottom"
                >
                  <span
                    role="button"
                    tabIndex={0}
                    className="action-button"
                    onClick={openEditModal}
                  >
                    <Icons.EditAlt data-test="edit-alt" />
                  </span>
                </Tooltip>
              )}
            </StyledActions>
          );
        },
        Header: t('Actions'),
        id: 'actions',
        hidden: false,
        disableSortBy: true,
      },
      {
        accessor: QueryObjectColumns.changed_by,
        hidden: true,
      },
    ],
    [
      userId,
      canEdit,
      canDelete,
      canExport,
      saveFavoriteStatus,
      favoriteStatus,
      activeRefreshData,
      addSuccessToast,
      addDangerToast,
      chartPermissions,
      getResourcePermissions,
    ],
  );

  const favoritesFilter: Filter = useMemo(
    () => ({
      Header: t('Favorite'),
      key: 'favorite',
      id: 'id',
      urlDisplay: 'favorite',
      input: 'select',
      operator: FilterOperator.chartIsFav,
      unfilteredLabel: t('Any'),
      selects: [
        { label: t('Yes'), value: true },
        { label: t('No'), value: false },
      ],
    }),
    [],
  );

  const filters: Filters = useMemo(() => {
    const filters_list = [
      {
        Header: t('Name'),
        key: 'search',
        id: 'slice_name',
        input: 'search',
        operator: FilterOperator.chartAllText,
      },
      // {
      //   Header: t('Type'),
      //   key: 'viz_type',
      //   id: 'viz_type',
      //   input: 'select',
      //   operator: FilterOperator.equals,
      //   unfilteredLabel: t('All'),
      //   selects: registry
      //     .keys()
      //     .filter(k => nativeFilterGate(registry.get(k)?.behaviors || []))
      //     .map(k => ({ label: registry.get(k)?.name || k, value: k }))
      //     .sort((a, b) => {
      //       if (!a.label || !b.label) {
      //         return 0;
      //       }

      //       if (a.label > b.label) {
      //         return 1;
      //       }
      //       if (a.label < b.label) {
      //         return -1;
      //       }

      //       return 0;
      //     }),
      // },
      {
        Header: t('Dataset'),
        key: 'dataset',
        id: 'datasource_id',
        input: 'select',
        operator: FilterOperator.equals,
        unfilteredLabel: t('All'),
        fetchSelects: createFetchDatasets,
        paginate: true,
      },
      // ...(isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM) && canReadTag
      //   ? [
      //       {
      //         Header: t('Tag'),
      //         key: 'tags',
      //         id: 'tags',
      //         input: 'select',
      //         operator: FilterOperator.chartTags,
      //         unfilteredLabel: t('All'),
      //         fetchSelects: loadTags,
      //       },
      //     ]
      //   : []),
      // {
      //   Header: t('Owner'),
      //   key: 'owner',
      //   id: 'owners',
      //   input: 'select',
      //   operator: FilterOperator.relationManyMany,
      //   unfilteredLabel: t('All'),
      //   fetchSelects: createFetchRelated(
      //     'chart',
      //     'owners',
      //     createErrorHandler(errMsg =>
      //       addDangerToast(
      //         t(
      //           'An error occurred while fetching chart owners values: %s',
      //           errMsg,
      //         ),
      //       ),
      //     ),
      //     props.user,
      //   ),
      //   paginate: true,
      // },
      {
        Header: t('Dashboard'),
        key: 'dashboards',
        id: 'dashboards',
        input: 'select',
        operator: FilterOperator.relationManyMany,
        unfilteredLabel: t('All'),
        fetchSelects: fetchDashboards,
        paginate: true,
      },
      ...(userId ? [favoritesFilter] : []),
      // {
      //   Header: t('Certified'),
      //   key: 'certified',
      //   id: 'id',
      //   urlDisplay: 'certified',
      //   input: 'select',
      //   operator: FilterOperator.chartIsCertified,
      //   unfilteredLabel: t('Any'),
      //   selects: [
      //     { label: t('Yes'), value: true },
      //     { label: t('No'), value: false },
      //   ],
      // },
      // {
      //   Header: t('Modified by'),
      //   key: 'changed_by',
      //   id: 'changed_by',
      //   input: 'select',
      //   operator: FilterOperator.relationOneMany,
      //   unfilteredLabel: t('All'),
      //   fetchSelects: createFetchRelated(
      //     'chart',
      //     'changed_by',
      //     createErrorHandler(errMsg =>
      //       t(
      //         'An error occurred while fetching dataset datasource values: %s',
      //         errMsg,
      //       ),
      //     ),
      //     props.user,
      //   ),
      //   paginate: true,
      // },
    ] as Filters;
    return filters_list;
  }, [addDangerToast, favoritesFilter, props.user]);

  const visibleFilters: Filters = useMemo(
    () => filters.filter(filter => filter.key !== 'favorite'),
    [filters],
  );
  const folderVisibleFilters: Filters = useMemo(
    () => visibleFilters,
    [visibleFilters],
  );

  const renderCard = useCallback(
    (chart: Chart) => {
      if (!chart.id) {
        return null;
      }
      const permissions = getResourcePermissions(chart.id);

      return (
        <ChartCard
          chart={chart}
          showThumbnails={
            userSettings
              ? userSettings.thumbnails
              : isFeatureEnabled(FeatureFlag.THUMBNAILS)
          }
          hasPerm={hasPerm}
          permissions={permissions}
          openChartEditModal={openChartEditModal}
          bulkSelectEnabled={bulkSelectEnabled}
          addDangerToast={addDangerToast}
          addSuccessToast={addSuccessToast}
          refreshData={() => {
            activeRefreshData();
          }}
          userId={userId}
          loading={activeLoading}
          favoriteStatus={favoriteStatus[chart.id]}
          saveFavoriteStatus={saveFavoriteStatus}
          handleBulkChartExport={handleBulkChartExport}
        />
      );
    },
    [
      addDangerToast,
      addSuccessToast,
      bulkSelectEnabled,
      favoriteStatus,
      hasPerm,
      activeLoading,
      activeRefreshData,
    ],
  );

  const subMenuButtons: SubMenuProps['buttons'] = [];
  if (canDelete || canExport) {
    subMenuButtons.push({
      name: t('Bulk select'),
      buttonStyle: 'secondary',
      'data-test': 'bulk-select',
      onClick: toggleBulkSelect,
    });
  }
  if (canCreate) {
    subMenuButtons.push({
      name: (
        <>
          <i className="fa fa-plus" /> {t('Chart')}
        </>
      ),
      buttonStyle: 'primary',
      onClick: () => {
        history.push('/chart/add');
      },
    });

    if (isFeatureEnabled(FeatureFlag.VERSIONED_EXPORT)) {
      subMenuButtons.push({
        name: (
          <Tooltip
            id="import-tooltip"
            title={t('Import charts')}
            placement="bottomRight"
          >
            <Icons.Import data-test="import-button" />
          </Tooltip>
        ),
        buttonStyle: 'link',
        onClick: openChartImportModal,
      });
    }
  }

  // const fetchChartData = useCallback(async (chartId: number) => {
  //   if (!chartId) {
  //     console.error('Chart ID is required');
  //     return;
  //   }
  //
  //   const formData = {
  //     slice_id: chartId,
  //     datasource: '4__table',
  //     viz_type: 'big_number',
  //     // ... 其他参数
  //   };
  //
  //   try {
  //     const response = await SupersetClient.post({
  //       endpoint: `/api/v1/chart/data`,
  //       jsonPayload: {
  //         form_data: formData,
  //         force: false,
  //         result_format: 'json',
  //         result_type: 'full'
  //       },
  //     });
  //     return response.json;
  //   } catch (error) {
  //     console.error('Failed to fetch chart data:', error);
  //     addDangerToast(t('Failed to fetch chart data'));
  //     return null;
  //   }
  // }, [addDangerToast]);

  // const handleFetchData = async (chart: Chart) => {
  //   if (!chart.id) {
  //     addDangerToast(t('Chart ID is required'));
  //     return;
  //   }
  //
  //   const formData = {
  //     slice_id: chart.id,
  //     datasource: chart.datasource_name_text,
  //     viz_type: chart.viz_type,
  //     // ... 其他必要的参数
  //   };
  //
  //   try {
  //     const response = await SupersetClient.post({
  //       endpoint: `/api/v1/chart/data`,
  //       jsonPayload: {
  //         form_data: formData,
  //         force: false,
  //         result_format: 'json',
  //         result_type: 'full'
  //       },
  //     });
  //     // 处理响应数据
  //     return response.json;
  //   } catch (error) {
  //     console.error('Failed to fetch chart data:', error);
  //     addDangerToast(t('Failed to fetch chart data'));
  //     return null;
  //   }
  // };

  // const handleViewChart = useCallback(async (chart: Chart) => {
  //   const data = await handleFetchData(chart);
  //   if (data) {
  //     // 处理数据...
  //   }
  // }, [handleFetchData]);

  return (
    <>
      <SubMenu name={t('Charts')} buttons={subMenuButtons} />
      {sliceCurrentlyEditing && (
        <PropertiesModal
          onHide={closeChartEditModal}
          onSave={handleChartUpdated}
          show
          slice={sliceCurrentlyEditing}
        />
      )}
      <ConfirmStatusChange
        title={t('Please confirm')}
        description={t('Are you sure you want to delete the selected charts?')}
        onConfirm={handleBulkChartDelete}
      >
        {confirmDelete => {
          const bulkActions: ListViewProps['bulkActions'] = [];
          if (canDelete) {
            bulkActions.push({
              key: 'delete',
              name: t('Delete'),
              type: 'danger',
              onSelect: confirmDelete,
            });
          }
          if (canExport) {
            bulkActions.push({
              key: 'export',
              name: t('Export'),
              type: 'primary',
              onSelect: handleBulkChartExport,
            });
          }
          return (
            <ListViewContainer>
              <ListView<Chart>
                key={`${location.pathname}${location.search}`}
                bulkActions={bulkActions}
                bulkSelectEnabled={bulkSelectEnabled}
                // cardSortSelectOptions={sortTypes}
                className="chart-list-view"
                columns={columns}
                count={activeChartCount}
                data={activeCharts}
                disableBulkSelect={toggleBulkSelect}
                refreshData={activeRefreshData}
                fetchData={activeFetchData}
                filters={filters}
                visibleFilters={isFolderView ? folderVisibleFilters : visibleFilters}
                initialSort={initialSort}
                loading={activeLoading}
                pageSize={PAGE_SIZE}
                renderCard={renderCard}
                enableBulkTag
                bulkTagResourceName="chart"
                addSuccessToast={addSuccessToast}
                addDangerToast={addDangerToast}
                showThumbnails={
                  userSettings
                    ? userSettings.thumbnails
                    : isFeatureEnabled(FeatureFlag.THUMBNAILS)
                }
                defaultViewMode={
                  !screens.md
                    ? 'card'
                    : isFeatureEnabled(FeatureFlag.LISTVIEWS_DEFAULT_CARD_VIEW)
                    ? 'card'
                    : 'table'
                }
              />
            </ListViewContainer>
          );
        }}
      </ConfirmStatusChange>

      <ImportModelsModal
        resourceName="chart"
        resourceLabel={t('chart')}
        passwordsNeededMessage={PASSWORDS_NEEDED_MESSAGE}
        confirmOverwriteMessage={CONFIRM_OVERWRITE_MESSAGE}
        addDangerToast={addDangerToast}
        addSuccessToast={addSuccessToast}
        onModelImport={handleChartImport}
        show={importingChart}
        onHide={closeChartImportModal}
        passwordFields={passwordFields}
        setPasswordFields={setPasswordFields}
        sshTunnelPasswordFields={sshTunnelPasswordFields}
        setSSHTunnelPasswordFields={setSSHTunnelPasswordFields}
        sshTunnelPrivateKeyFields={sshTunnelPrivateKeyFields}
        setSSHTunnelPrivateKeyFields={setSSHTunnelPrivateKeyFields}
        sshTunnelPrivateKeyPasswordFields={sshTunnelPrivateKeyPasswordFields}
        setSSHTunnelPrivateKeyPasswordFields={
          setSSHTunnelPrivateKeyPasswordFields
        }
      />
      {preparingExport && <Loading />}
    </>
  );
}

export default withToasts(ChartList);
