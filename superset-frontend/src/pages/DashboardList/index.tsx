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
  isFeatureEnabled,
  FeatureFlag,
  styled,
  SupersetClient,
  t,
} from '@superset-ui/core';
import { useSelector } from 'react-redux';
import React, { useState, useMemo, useCallback, useEffect, useRef } from 'react';
import { Link, useHistory, useLocation } from 'react-router-dom';
import rison from 'rison';
import {
  createErrorHandler,
  handleDashboardDelete,
} from 'src/views/CRUD/utils';
import { useListViewResource, useFavoriteStatus } from 'src/views/CRUD/hooks';
import ConfirmStatusChange from 'src/components/ConfirmStatusChange';
import { TagsList } from 'src/components/Tags';
import handleResourceExport from 'src/utils/export';
import Loading from 'src/components/Loading';
import SubMenu, { SubMenuProps } from 'src/features/home/SubMenu';
import ListView, {
  ListViewProps,
  Filter,
  Filters,
  FilterValue,
  FilterOperator,
} from 'src/components/ListView';
import { FetchDataConfig } from 'src/components/ListView/types';
import { dangerouslyGetItemDoNotUse } from 'src/utils/localStorageHelpers';
import Owner from 'src/types/Owner';
import Tag from 'src/types/TagType';
import withToasts from 'src/components/MessageToasts/withToasts';
import FacePile from 'src/components/FacePile';
import Icons from 'src/components/Icons';
import DeleteModal from 'src/components/DeleteModal';
import FaveStar from 'src/components/FaveStar';
import PropertiesModal from 'src/dashboard/components/PropertiesModal';
import { Tooltip } from 'src/components/Tooltip';
import ImportModelsModal from 'src/components/ImportModal/index';

import Dashboard from 'src/dashboard/containers/Dashboard';
import {
  Dashboard as CRUDDashboard,
  QueryObjectColumns,
} from 'src/views/CRUD/types';
import CertifiedBadge from 'src/components/CertifiedBadge';
// import { loadTags } from 'src/components/Tags/utils';
import DashboardCard from 'src/features/dashboards/DashboardCard';
import { DashboardStatus } from 'src/features/dashboards/types';
import { UserWithPermissionsAndRoles } from 'src/types/bootstrapTypes';
import { findPermission } from 'src/utils/findPermission';
import { ModifiedInfo } from 'src/components/AuditInfo';
import useBreakpoint from 'antd/lib/grid/hooks/useBreakpoint';
import {
  DASHBOARD_FOLDER_QUERY_KEY,
  DashboardFolder,
  emitDashboardFoldersUpdated,
  removeDashboardFromFolder,
} from 'src/features/dashboards/folders/api';
import useDashboardFolders from 'src/features/dashboards/folders/useDashboardFolders';

const ListViewContainer = styled.div`
  background-color: #FFFFFF;
  padding: ${({ theme }) => theme.gridUnit * 4}px;
  min-height: calc(100vh - 150px);
  margin: 0 16px 16px;
  border-radius: ${({ theme }) => theme.borderRadius}px;
`;

const PAGE_SIZE = 25;
const PASSWORDS_NEEDED_MESSAGE = t(
  'The passwords for the databases below are needed in order to ' +
    'import them together with the dashboards. Please note that the ' +
    '"Secure Extra" and "Certificate" sections of ' +
    'the database configuration are not present in export files, and ' +
    'should be added manually after the import if they are needed.',
);
const CONFIRM_OVERWRITE_MESSAGE = t(
  'You are importing one or more dashboards that already exist. ' +
    'Overwriting might cause you to lose some of your work. Are you ' +
    'sure you want to overwrite?',
);

interface DashboardListProps {
  addDangerToast: (msg: string) => void;
  addSuccessToast: (msg: string) => void;
  user: {
    userId: string | number;
    firstName: string;
    lastName: string;
  };
}

export interface Dashboard {
  changed_by_name: string;
  changed_on_delta_humanized: string;
  changed_by: string;
  dashboard_title: string;
  id: number;
  published: boolean;
  url: string;
  thumbnail_url: string;
  owners: Owner[];
  tags: Tag[];
  created_by: object;
}

type FolderDashboardsState = {
  loading: boolean;
  collection: Dashboard[];
  count: number;
  lastFetchDataConfig: FetchDataConfig | null;
};

const Actions = styled.div`
  color: ${({ theme }) => theme.colors.grayscale.base};
`;

function DashboardList(props: DashboardListProps) {
  const { addDangerToast, addSuccessToast, user } = props;
  const screens = useBreakpoint();
  const history = useHistory();
  const location = useLocation();
  const { roles } = useSelector<any, UserWithPermissionsAndRoles>(
    state => state.user,
  );
  const canReadTag = findPermission('can_read', 'Tag', roles);

  const {
    state: {
      loading,
      resourceCount: dashboardCount,
      resourceCollection: dashboards,
      bulkSelectEnabled,
    },
    setResourceCollection: setDashboards,
    hasPerm,
    fetchData,
    toggleBulkSelect,
    refreshData,
    getResourcePermissions,
  } = useListViewResource<Dashboard>(
    'dashboard',
    t('dashboard'),
    addDangerToast,
  );
  const [folderState, setFolderState] = useState<FolderDashboardsState>({
    loading: false,
    collection: [],
    count: 0,
    lastFetchDataConfig: null,
  });
  const selectedFolderId = useMemo(
    () => new URLSearchParams(location.search).get(DASHBOARD_FOLDER_QUERY_KEY),
    [location.search],
  );
  const { dashboardFolders } = useDashboardFolders();
  const selectedFolder = useMemo<DashboardFolder | null>(
    () =>
      dashboardFolders.find(folder => folder.id === selectedFolderId) ?? null,
    [dashboardFolders, selectedFolderId],
  );
  const isFolderView = !!selectedFolder;
  const activeDashboards = isFolderView ? folderState.collection : dashboards;
  const activeDashboardCount = isFolderView ? folderState.count : dashboardCount;
  const activeLoading = isFolderView ? folderState.loading : loading;
  const dashboardIds = useMemo(
    () =>
      isFolderView
        ? selectedFolder?.items.map(item => item.dashboardId) ?? []
        : dashboards.map(d => d.id),
    [dashboards, isFolderView, selectedFolder],
  );
  const [saveFavoriteStatus, favoriteStatus] = useFavoriteStatus(
    'dashboard',
    dashboardIds,
    addDangerToast,
  );
  const favoriteStatusRef = useRef(favoriteStatus);

  useEffect(() => {
    favoriteStatusRef.current = favoriteStatus;
  }, [favoriteStatus]);

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

  const fetchFolderDashboards = useCallback(
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

      const dashboardsInFolder = await Promise.all(
        selectedFolder.items.map(async item => {
          try {
            const { json } = await SupersetClient.get({
              endpoint: `/api/v1/dashboard/${item.dashboardId}`,
            });
            const dashboard = json?.result;

            if (!dashboard?.id) {
              return { dashboard: null, staleItemId: item.id };
            }

            return {
              dashboard: {
                ...dashboard,
                changed_by: dashboard.changed_by || '',
                changed_by_name: dashboard.changed_by_name || '',
                changed_on_delta_humanized:
                  dashboard.changed_on_delta_humanized || '',
                dashboard_title: dashboard.dashboard_title || item.name,
                owners: dashboard.owners || [],
                published: !!dashboard.published,
                status: dashboard.published
                  ? DashboardStatus.PUBLISHED
                  : DashboardStatus.DRAFT,
                tags: dashboard.tags || [],
                url: dashboard.url || item.url,
              } as Dashboard,
              staleItemId: null,
            };
          } catch {
            return { dashboard: null, staleItemId: item.id };
          }
        }),
      );

      const staleItemIds = dashboardsInFolder
        .map(result => result.staleItemId)
        .filter(Boolean) as string[];

      if (staleItemIds.length) {
        await Promise.all(
          selectedFolder.items
            .filter(item => staleItemIds.includes(item.id))
            .map(item => removeDashboardFromFolder(selectedFolder.id, item.id)),
        );
        emitDashboardFoldersUpdated();
      }

      const collection = dashboardsInFolder
        .map(result => result.dashboard)
        .filter(Boolean) as Dashboard[];
      const nameFilter = filters.find(
        filter => filter.id === 'dashboard_title',
      );
      const publishedFilter = filters.find(filter => filter.id === 'published');
      const favoriteFilter = filters.find(
        filter => (filter.urlDisplay || filter.id) === 'favorite',
      );
      const searchValue =
        typeof nameFilter?.value === 'string'
          ? nameFilter.value.trim().toLowerCase()
          : '';
      const publishedValue = getSelectBooleanValue(publishedFilter?.value);
      const favoriteValue = getSelectBooleanValue(favoriteFilter?.value);
      const filteredCollection = searchValue
        ? collection.filter(dashboard => {
            const title = dashboard.dashboard_title?.toLowerCase() || '';
            const slug = String(
              (dashboard as Dashboard & { slug?: string }).slug || '',
            ).toLowerCase();
            return (
              title.includes(searchValue) || slug.includes(searchValue)
            );
          })
        : collection;
      const visibilityFilteredCollection = filteredCollection.filter(
        dashboard => {
          const matchesPublished =
            typeof publishedValue === 'boolean'
              ? dashboard.published === publishedValue
              : true;
          const matchesFavorite =
            typeof favoriteValue === 'boolean'
              ? Boolean(favoriteStatusRef.current[dashboard.id]) === favoriteValue
              : true;

          return matchesPublished && matchesFavorite;
        },
      );
      const sortedCollection = [...visibilityFilteredCollection].sort((a, b) => {
        const sortKey = sortBy[0]?.id || 'changed_on_delta_humanized';
        const sortDesc = sortBy[0]?.desc ?? true;

        const valueA = a[sortKey as keyof Dashboard];
        const valueB = b[sortKey as keyof Dashboard];

        if (typeof valueA === 'boolean' && typeof valueB === 'boolean') {
          return sortDesc
            ? Number(valueB) - Number(valueA)
            : Number(valueA) - Number(valueB);
        }

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
    [dashboardFolders, getSelectBooleanValue, selectedFolder],
  );
  const activeFetchData = isFolderView ? fetchFolderDashboards : fetchData;
  const activeRefreshData = useCallback(
    (provideConfig?: FetchDataConfig) => {
      if (isFolderView) {
        if (folderState.lastFetchDataConfig) {
          return fetchFolderDashboards(folderState.lastFetchDataConfig);
        }
        if (provideConfig) {
          return fetchFolderDashboards(provideConfig);
        }
        return null;
      }

      return refreshData(provideConfig);
    },
    [fetchFolderDashboards, folderState.lastFetchDataConfig, isFolderView, refreshData],
  );

  const [dashboardToEdit, setDashboardToEdit] = useState<Dashboard | null>(
    null,
  );
  const [dashboardToDelete, setDashboardToDelete] =
    useState<CRUDDashboard | null>(null);

  const [importingDashboard, showImportModal] = useState<boolean>(false);
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

  const [globalPermissions, setGlobalPermissions] = useState<{
    can_write: boolean;
  }>({
    can_write: false,
  });

  const userKey = user?.userId
    ? dangerouslyGetItemDoNotUse(user.userId.toString(), {
        thumbnails: isFeatureEnabled(FeatureFlag.THUMBNAILS),
      })
    : null;

  useEffect(() => {
    const fetchPermissions = async () => {
      try {
        const response = await SupersetClient.get({
          endpoint: `/api/v1/dashboard/_info`,
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

  const canCreate = globalPermissions.can_write;
  const canEdit = hasPerm('can_write');
  const canDelete = hasPerm('can_write');
  const canExport =
    hasPerm('can_export') && isFeatureEnabled(FeatureFlag.VERSIONED_EXPORT);

  const initialSort = [{ id: 'changed_on_delta_humanized', desc: true }];
  const nameFilter: Filter = useMemo(
    () => ({
      Header: t('Name'),
      key: 'search',
      id: 'dashboard_title',
      input: 'search',
      operator: FilterOperator.titleOrSlug,
    }),
    [],
  );

  useEffect(() => {
    if (!user?.userId) {
      return;
    }

    if (location.pathname !== '/dashboard/list/' || location.search) {
      return;
    }

    const favoriteQuery = rison.encode({
      favorite: {
        label: t('Yes'),
        value: true,
      },
    });

    history.replace(
      `/dashboard/list/?pageIndex=0&sortColumn=changed_on_delta_humanized&sortOrder=desc&viewMode=card&filters=${favoriteQuery}`,
    );
  }, [history, location.pathname, location.search, user?.userId]);

  function openDashboardEditModal(dashboard: Dashboard) {
    setDashboardToEdit(dashboard);
  }

  function handleDashboardEdit(edits: Dashboard) {
    return SupersetClient.get({
      endpoint: `/api/v1/dashboard/${edits.id}`,
    }).then(
      ({ json = {} }) => {
        setDashboards(
          dashboards.map(dashboard => {
            if (dashboard.id === json?.result?.id) {
              const {
                changed_by_name,
                changed_by,
                dashboard_title = '',
                slug = '',
                json_metadata = '',
                changed_on_delta_humanized,
                url = '',
                certified_by = '',
                certification_details = '',
                owners,
                tags,
              } = json.result;
              return {
                ...dashboard,
                changed_by_name,
                changed_by,
                dashboard_title,
                slug,
                json_metadata,
                changed_on_delta_humanized,
                url,
                certified_by,
                certification_details,
                owners,
                tags,
              };
            }
            return dashboard;
          }),
        );
      },
      createErrorHandler(errMsg =>
        addDangerToast(
          t('An error occurred while fetching dashboards: %s', errMsg),
        ),
      ),
    );
  }

  const openDashboardImportModal = () => {
    showImportModal(true);
  };

  const closeDashboardImportModal = () => {
    showImportModal(false);
  };

  const handleDashboardImport = () => {
    showImportModal(false);
    refreshData();
    addSuccessToast(t('Dashboard imported'));
  };

  const handleBulkDashboardExport = (dashboardsToExport: Dashboard[]) => {
    setPreparingExport(true);
    try {
      const ids = dashboardsToExport.map(({ id }) => id);
      handleResourceExport(
        'dashboard',
        ids,
        () => {
          setPreparingExport(false);
        },
        200,
      );
    } catch (err) {
      setPreparingExport(false);
      addDangerToast(t('There was an issue with exporting the dashboards'));
    }
  };

  function handleBulkDashboardDelete(dashboardsToDelete: Dashboard[]) {
    return SupersetClient.delete({
      endpoint: `/api/v1/dashboard/?q=${rison.encode(
        dashboardsToDelete.map(({ id }) => id),
      )}`,
    }).then(
      ({ json = {} }) => {
        refreshData();
        addSuccessToast(json.message);
      },
      createErrorHandler(errMsg =>
        addDangerToast(
          t('There was an issue deleting the selected dashboards: ', errMsg),
        ),
      ),
    );
  }

  const columns = useMemo(
    () => [
      {
        Cell: ({
          row: {
            original: { id },
          },
        }: any) =>
          user?.userId && (
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
        hidden: !user?.userId,
      },
      {
        Cell: ({
          row: {
            original: {
              url,
              dashboard_title: dashboardTitle,
              certified_by: certifiedBy,
              certification_details: certificationDetails,
            },
          },
        }: any) => (
          <Link to={url}>
            {certifiedBy && (
              <>
                <CertifiedBadge
                  certifiedBy={certifiedBy}
                  details={certificationDetails}
                />{' '}
              </>
            )}
            {dashboardTitle}
          </Link>
        ),
        Header: t('Name'),
        accessor: 'dashboard_title',
      },
      {
        Cell: ({
          row: {
            original: { status },
          },
        }: any) =>
          status === DashboardStatus.PUBLISHED ? t('Published') : t('Draft'),
        Header: t('Status'),
        accessor: 'published',
        size: 'xl',
      },
      {
        Cell: ({
          row: {
            original: { tags = [] },
          },
        }: {
          row: {
            original: {
              tags: Tag[];
            };
          };
        }) => (
          // Only show custom type tags
          <TagsList
            tags={tags.filter(
              (tag: Tag) => tag.type === 'TagTypes.custom' || tag.type === 1,
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
        accessor: 'changed_on_delta_humanized',
        size: 'xl',
      },
      {
        Cell: ({ row: { original } }: any) => {
          const handleDelete = () =>
            handleDashboardDelete(
              original,
              activeRefreshData,
              addSuccessToast,
              addDangerToast,
            );
          const handleEdit = () => openDashboardEditModal(original);
          const handleExport = () => handleBulkDashboardExport([original]);

          const permissions = getResourcePermissions(original.id);

          return (
            <Actions className="actions">
              {permissions.can_delete && (
                <ConfirmStatusChange
                  title={t('Please confirm')}
                  description={
                    <>
                      {t('Are you sure you want to delete')}{' '}
                      <b>{original.dashboard_title}</b>?
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
                    onClick={handleEdit}
                  >
                    <Icons.EditAlt data-test="edit-alt" />
                  </span>
                </Tooltip>
              )}
            </Actions>
          );
        },
        Header: t('Actions'),
        id: 'actions',
        disableSortBy: true,
      },
      {
        accessor: QueryObjectColumns.changed_by,
        hidden: true,
      },
    ],
    [
      user?.userId,
      canEdit,
      canDelete,
      canExport,
      saveFavoriteStatus,
      favoriteStatus,
      activeRefreshData,
      addSuccessToast,
      addDangerToast,
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
      operator: FilterOperator.dashboardIsFav,
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
      nameFilter,
      {
        Header: t('Status'),
        key: 'published',
        id: 'published',
        input: 'select',
        operator: FilterOperator.equals,
        unfilteredLabel: t('Any'),
        selects: [
          { label: t('Published'), value: true },
          { label: t('Draft'), value: false },
        ],
      },
      // ...(isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM) && canReadTag
      //   ? [
      //       {
      //         Header: t('Tag'),
      //         key: 'tags',
      //         id: 'tags',
      //         input: 'select',
      //         operator: FilterOperator.dashboardTags,
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
      //     'dashboard',
      //     'owners',
      //     createErrorHandler(errMsg =>
      //       addDangerToast(
      //         t(
      //           'An error occurred while fetching dashboard owner values: %s',
      //           errMsg,
      //         ),
      //       ),
      //     ),
      //     props.user,
      //   ),
      //   paginate: true,
      // },
      ...(user?.userId ? [favoritesFilter] : []),
      // {
      //   Header: t('Certified'),
      //   key: 'certified',
      //   id: 'id',
      //   urlDisplay: 'certified',
      //   input: 'select',
      //   operator: FilterOperator.dashboardIsCertified,
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
      //     'dashboard',
      //     'changed_by',
      //     createErrorHandler(errMsg =>
      //       t(
      //         'An error occurred while fetching dataset datasource values: %s',
      //         errMsg,
      //       ),
      //     ),
      //     user,
      //   ),
      //   paginate: true,
      // },
    ] as Filters;
    return filters_list;
  }, [canReadTag, favoritesFilter, nameFilter, user?.userId]);

  const visibleFilters: Filters = useMemo(
    () => filters.filter(filter => !['published', 'favorite'].includes(filter.key)),
    [filters],
  );
  const folderVisibleFilters: Filters = useMemo(
    () => visibleFilters.filter(filter => filter.key === 'search'),
    [visibleFilters],
  );

  const renderCard = useCallback(
    (dashboard: Dashboard) => {
      if (!dashboard.id) {
        return null;
      }
      const permissions = getResourcePermissions(dashboard.id);

      return (
        <DashboardCard
          dashboard={dashboard}
          hasPerm={hasPerm}
          permissions={permissions}
          bulkSelectEnabled={bulkSelectEnabled}
          showThumbnails={
            userKey
              ? userKey.thumbnails
              : isFeatureEnabled(FeatureFlag.THUMBNAILS)
          }
          userId={user?.userId}
          loading={loading}
          openDashboardEditModal={openDashboardEditModal}
          saveFavoriteStatus={saveFavoriteStatus}
          favoriteStatus={favoriteStatus[dashboard.id]}
          handleBulkDashboardExport={handleBulkDashboardExport}
          onDelete={dashboard => setDashboardToDelete(dashboard)}
        />
      );
    },
    [
      bulkSelectEnabled,
      favoriteStatus,
      hasPerm,
      loading,
      user?.userId,
      saveFavoriteStatus,
      userKey,
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
          <i className="fa fa-plus" /> {t('Dashboard')}
        </>
      ),
      buttonStyle: 'primary',
      onClick: () => {
        window.location.assign('/dashboard/new');
      },
    });

    if (isFeatureEnabled(FeatureFlag.VERSIONED_EXPORT)) {
      subMenuButtons.push({
        name: (
          <Tooltip
            id="import-tooltip"
            title={t('Import dashboards')}
            placement="bottomRight"
          >
            <Icons.Import data-test="import-button" />
          </Tooltip>
        ),
        buttonStyle: 'link',
        onClick: openDashboardImportModal,
      });
    }
  }

  return (
    <>
      <SubMenu
        name={isFolderView ? selectedFolder?.name || t('Dashboards') : t('Dashboards')}
        buttons={!screens.md ? [] : subMenuButtons}
      />
      <ConfirmStatusChange
        title={t('Please confirm')}
        description={t(
          'Are you sure you want to delete the selected dashboards?',
        )}
        onConfirm={handleBulkDashboardDelete}
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
              onSelect: handleBulkDashboardExport,
            });
          }
          return (
            <>
              {dashboardToEdit && (
                <PropertiesModal
                  dashboardId={dashboardToEdit.id}
                  show
                  onHide={() => setDashboardToEdit(null)}
                  onSubmit={handleDashboardEdit}
                />
              )}
              {dashboardToDelete && (
                <DeleteModal
                  description={
                    <>
                      {t('Are you sure you want to delete')}{' '}
                      <b>{dashboardToDelete.dashboard_title}</b>?
                    </>
                  }
                  onConfirm={() => {
                    handleDashboardDelete(
                      dashboardToDelete,
                      activeRefreshData,
                      addSuccessToast,
                      addDangerToast,
                      undefined,
                      user?.userId,
                    );
                    setDashboardToDelete(null);
                  }}
                  onHide={() => setDashboardToDelete(null)}
                  open={!!dashboardToDelete}
                  title={t('Please confirm')}
                />
              )}
              <ListViewContainer>
                <ListView<Dashboard>
                  key={`${location.pathname}${location.search}`}
                  bulkActions={bulkActions}
                  bulkSelectEnabled={bulkSelectEnabled}
                  // cardSortSelectOptions={sortTypes}
                  className="dashboard-list-view"
                  columns={columns}
                  count={activeDashboardCount}
                  data={activeDashboards}
                  disableBulkSelect={toggleBulkSelect}
                  fetchData={activeFetchData}
                  refreshData={activeRefreshData}
                  filters={filters}
                  visibleFilters={isFolderView ? folderVisibleFilters : visibleFilters}
                  showFilters={screens.md}
                  initialSort={initialSort}
                  loading={activeLoading}
                  pageSize={PAGE_SIZE}
                  addSuccessToast={addSuccessToast}
                  addDangerToast={addDangerToast}
                  showThumbnails={
                    userKey
                      ? userKey.thumbnails
                      : isFeatureEnabled(FeatureFlag.THUMBNAILS)
                  }
                  renderCard={renderCard}
                  defaultViewMode={
                    !screens.md
                      ? 'card'
                      : isFeatureEnabled(FeatureFlag.LISTVIEWS_DEFAULT_CARD_VIEW)
                      ? 'card'
                      : 'table'
                  }
                  enableBulkTag
                  bulkTagResourceName="dashboard"
                />
              </ListViewContainer>
            </>
          );
        }}
      </ConfirmStatusChange>

      <ImportModelsModal
        resourceName="dashboard"
        resourceLabel={t('dashboard')}
        passwordsNeededMessage={PASSWORDS_NEEDED_MESSAGE}
        confirmOverwriteMessage={CONFIRM_OVERWRITE_MESSAGE}
        addDangerToast={addDangerToast}
        addSuccessToast={addSuccessToast}
        onModelImport={handleDashboardImport}
        show={importingDashboard}
        onHide={closeDashboardImportModal}
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

export default withToasts(DashboardList);
