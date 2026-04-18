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
import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useSelector } from 'react-redux';
import {
  FeatureFlag,
  isFeatureEnabled,
  styled,
  css,
  useTheme,
  SupersetTheme,
  SupersetClient,
  t,
} from '@superset-ui/core';
import rison from 'rison';
import { debounce } from 'lodash';
import { Global } from '@emotion/react';
import { getUrlParam } from 'src/utils/urlUtils';
import { Grid } from 'src/components';
import Modal from 'src/components/Modal';
import { Input } from 'src/components/Input';
import { MainNav as DropdownMenu, MenuMode } from 'src/components/Menu';
import { Tooltip } from 'src/components/Tooltip';
import { NavLink, useHistory, useLocation } from 'react-router-dom';
import { GenericLink } from 'src/components/GenericLink/GenericLink';
import { useToasts } from 'src/components/MessageToasts/withToasts';
import { useUiConfig } from 'src/components/UiConfigContext';
import { URL_PARAMS } from 'src/constants';
import {
  MenuObjectChildProps,
  MenuObjectProps,
  MenuData,
  UserWithPermissionsAndRoles,
} from 'src/types/bootstrapTypes';
import getBootstrapData from 'src/utils/getBootstrapData';
import {
  CloseOutlined,
  DashboardOutlined,
  BarChartOutlined,
  DatabaseOutlined,
  ConsoleSqlOutlined,
  DeleteOutlined,
  EditOutlined,
  FileOutlined,
  FileTextOutlined,
  FolderOutlined,
  MenuOutlined,
  PlusOutlined,
  ReadOutlined,
  RobotOutlined,
  PartitionOutlined,
  StarOutlined,
} from '@ant-design/icons';
import { Button } from 'antd';
import TagType from 'src/types/TagType';
import {
  addTag,
  deleteTaggedObjects,
  OBJECT_TYPES,
} from 'src/features/tags/tags';
import {
  addDashboardToFolder,
  createDashboardFolder,
  DASHBOARD_FOLDER_QUERY_KEY,
  DashboardFolder,
  DashboardFolderItem,
  deleteDashboardFolder,
  renameDashboardFolder,
} from 'src/features/dashboards/folders/api';
import useDashboardFolders from 'src/features/dashboards/folders/useDashboardFolders';
import {
  CHART_FOLDER_QUERY_KEY,
  ChartFolder,
  createChartFolder,
  deleteChartFolder,
  renameChartFolder as renameChartFolderApi,
} from 'src/features/charts/folders/api';
import useChartFolders from 'src/features/charts/folders/useChartFolders';
import RightMenu from './RightMenu';

const bootstrapData = getBootstrapData();

const iconMap: Record<string, React.ReactNode> = {
  'Dashboards': <DashboardOutlined />,
  'Charts': <BarChartOutlined />,
  'Datasets': <DatabaseOutlined />,
  'SQL Lab': <ConsoleSqlOutlined />,
  'SQL': <ConsoleSqlOutlined />,
  'Copilot': <RobotOutlined />,
  'Workflow': <PartitionOutlined />,
  '文档': <ReadOutlined />,
};

interface MenuProps {
  data: MenuData;
  isFrontendRoute?: (path?: string) => boolean;
}

const CHARTS_ROOT_KEY = 'Charts';
const DASHBOARDS_ROOT_KEY = 'Dashboards';
const CHART_FAVORITES_KEY = 'chart-my-favorites';
const DASHBOARD_FAVORITES_KEY = 'dashboard-my-favorites';
const DASHBOARD_DRAFTS_KEY = 'dashboard-my-drafts';
const ADMIN_ROLE_NAME = 'admin';
const CHART_FOLDER_MENU_KEY_PREFIX = 'chart-folder-menu';
const CHART_FOLDER_ITEM_MENU_KEY_PREFIX = 'chart-folder-item';
const DASHBOARD_FOLDER_MENU_KEY_PREFIX = 'dashboard-folder-menu';
const DASHBOARD_FOLDER_ITEM_MENU_KEY_PREFIX = 'dashboard-folder-item';

const normalizePath = (path?: string) => (path || '').replace(/\/+$/, '');

const getPathnameFromUrl = (url?: string) => {
  if (!url) {
    return '';
  }

  try {
    return normalizePath(new URL(url, window.location.origin).pathname);
  } catch {
    return normalizePath(url.split('?')[0]);
  }
};

const getDashboardFolderMenuKey = (folderId: string) =>
  `${DASHBOARD_FOLDER_MENU_KEY_PREFIX}-${folderId}`;

const getChartFolderMenuKey = (folderId: string) =>
  `${CHART_FOLDER_MENU_KEY_PREFIX}-${folderId}`;

const getDashboardFolderItemMenuKey = (itemId: string) =>
  `${DASHBOARD_FOLDER_ITEM_MENU_KEY_PREFIX}-${itemId}`;

const getChartFolderItemMenuKey = (itemId: string) =>
  `${CHART_FOLDER_ITEM_MENU_KEY_PREFIX}-${itemId}`;

const isChartFolderItemMenuKey = (key?: string | null) =>
  !!key && key.startsWith(`${CHART_FOLDER_ITEM_MENU_KEY_PREFIX}-`);

const isDashboardFolderItemMenuKey = (key?: string | null) =>
  !!key && key.startsWith(`${DASHBOARD_FOLDER_ITEM_MENU_KEY_PREFIX}-`);

const isChartFolderMenuKey = (key?: string | null) =>
  !!key && key.startsWith(`${CHART_FOLDER_MENU_KEY_PREFIX}-`);

const isDashboardFolderMenuKey = (key?: string | null) =>
  !!key && key.startsWith(`${DASHBOARD_FOLDER_MENU_KEY_PREFIX}-`);

const isChartMenuKey = (key?: string | null) =>
  key === CHARTS_ROOT_KEY ||
  key === CHART_FAVORITES_KEY ||
  isChartFolderMenuKey(key) ||
  isChartFolderItemMenuKey(key);

const isDashboardMenuKey = (key?: string | null) =>
  key === DASHBOARDS_ROOT_KEY ||
  key === DASHBOARD_FAVORITES_KEY ||
  key === DASHBOARD_DRAFTS_KEY ||
  isDashboardFolderMenuKey(key) ||
  isDashboardFolderItemMenuKey(key);

const getChartListKeyFromFilters = (filters?: string | null) => {
  if (!filters) {
    return CHARTS_ROOT_KEY;
  }

  try {
    const decodedFilters = rison.decode(filters) as Record<string, any>;
    const favoriteFilter = decodedFilters.favorite;

    if (favoriteFilter === true || favoriteFilter?.value === true) {
      return CHART_FAVORITES_KEY;
    }
  } catch {
    // ignore decode errors and fall back to string matching below
  }

  if (filters.includes('favorite')) {
    return CHART_FAVORITES_KEY;
  }

  return CHARTS_ROOT_KEY;
};

const getDashboardListKeyFromFilters = (filters?: string | null) => {
  if (!filters) {
    return DASHBOARDS_ROOT_KEY;
  }

  try {
    const decodedFilters = rison.decode(filters) as Record<string, any>;
    const favoriteFilter = decodedFilters.favorite;
    const publishedFilter = decodedFilters.published;

    if (favoriteFilter === true || favoriteFilter?.value === true) {
      return DASHBOARD_FAVORITES_KEY;
    }

    if (publishedFilter === false || publishedFilter?.value === false) {
      return DASHBOARD_DRAFTS_KEY;
    }
  } catch {
    // ignore decode errors and fall back to string matching below
  }

  if (filters.includes('favorite')) {
    return DASHBOARD_FAVORITES_KEY;
  }

  if (filters.includes('published')) {
    return DASHBOARD_DRAFTS_KEY;
  }

  return DASHBOARDS_ROOT_KEY;
};

const normalizeDashboardUrl = (url: string | undefined, dashboardId: number) =>
  url || `/superset/dashboard/${dashboardId}/`;

const normalizeChartUrl = (url: string | undefined, chartId: number) =>
  url || `/explore/?slice_id=${chartId}`;

const DashboardMenuItemIcon = styled.img`
  width: ${({ theme }) => theme.gridUnit * 4.5}px;
  height: ${({ theme }) => theme.gridUnit * 4.5}px;
  object-fit: contain;
  margin-bottom: 2px;
`;

const StyledHeader = styled.header`
  ${({ theme }) => `
      background-color: ${theme.colors.grayscale.light5};
      margin-bottom: 2px;
      z-index: 1000;
      box-shadow: 2px 0 8px 0 rgba(0, 0, 0, 0.05);
      width: 220px;
      flex-shrink: 0;
      height: 100vh;
      overflow-y: auto;

      .navbar-brand-container {
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .caret {
        display: none;
      }
      .navbar-brand {
        display: flex;
        flex-direction: column;
        justify-content: center;
        /* must be exactly the height of the Antd navbar */
        min-height: 60px;
        padding: ${theme.gridUnit}px
          ${theme.gridUnit * 2}px
          ${theme.gridUnit}px
          ${theme.gridUnit * 2}px;
        max-width: ${theme.gridUnit * theme.brandIconMaxWidth}px;
        img {
          height: 100%;
          object-fit: contain;
        }
      }
      .navbar-brand-text {
        border-left: 1px solid ${theme.colors.grayscale.light2};
        border-right: 1px solid ${theme.colors.grayscale.light2};
        height: 100%;
        color: ${theme.colors.grayscale.dark1};
        padding-left: ${theme.gridUnit * 4}px;
        padding-right: ${theme.gridUnit * 4}px;
        margin-right: ${theme.gridUnit * 6}px;
        font-size: ${theme.gridUnit * 4}px;
        float: left;
        display: flex;
        flex-direction: column;
        justify-content: center;

        span {
          max-width: ${theme.gridUnit * 58}px;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }
        @media (max-width: 1127px) {
          display: none;
        }
      }

      @media (max-width: 767px) {
        .navbar-brand {
          float: none;
        }
      }

      .ant-menu-submenu-selected,
      .menu-submenu-manual-selected,
      .ant-menu-submenu:has(.ant-menu-item-selected),
      .ant-menu-submenu:has(.menu-item-manual-selected),
      .ant-menu-submenu:has(.menu-link-manual-selected),
      .ant-menu-submenu:has(.is-active) {
        > .ant-menu-submenu-title {
          color: ${theme.colors.primary.base} !important;
          .anticon {
            color: ${theme.colors.primary.base} !important;
          }
        }
      }

      .ant-menu-item-selected,
      .menu-item-manual-selected,
      .ant-menu-item:has(.menu-link-manual-selected),
      .ant-menu-item:has(.is-active) {
        background-color: #E7F6EC !important;
        color: ${theme.colors.primary.base} !important;
        
        .anticon {
          color: ${theme.colors.primary.base} !important;
        }
        
        a {
          color: ${theme.colors.primary.base} !important;
        }

        &::after {
          content: '';
          position: absolute;
          top: 0;
          right: 0;
          bottom: 0;
          border-right: 3px solid ${theme.colors.primary.base} !important;
          transform: scaleY(1) !important;
          opacity: 1 !important;
        }

        &:hover {
          background-color: #E7F6EC !important;
          color: ${theme.colors.primary.base} !important;
          
          .anticon {
            color: ${theme.colors.primary.base} !important;
          }
          
          a {
            color: ${theme.colors.primary.base} !important;
          }
        }
      }

      .ant-menu-item:not(.ant-menu-item-selected):not(:has(.is-active)) {
        &:hover {
          background-color: ${theme.colors.primary.light5};
          color: ${theme.colors.primary.base};

          .anticon {
            color: ${theme.colors.primary.base};
          }

          a {
            color: ${theme.colors.primary.base};
            text-decoration: none;
          }
        }
      }

      .menu-node-content {
        display: inline-flex;
        align-items: center;
        justify-content: space-between;
        gap: ${theme.gridUnit}px;
        width: calc(100% - 24px);
        max-width: calc(100% - 24px);
        min-width: 0;
        padding: 0;
        border: 0;
        background: transparent;
        color: inherit;
        font: inherit;
        text-align: left;
      }

      .menu-node-label {
        display: flex;
        align-items: center;
        gap: ${theme.gridUnit}px;
        min-width: 0;
        flex: 1;
      }

      .menu-node-label-text {
        overflow: hidden;
        text-overflow: ellipsis;
        white-space: nowrap;
      }

      .menu-node-actions {
        display: flex;
        align-items: center;
        gap: ${theme.gridUnit / 2}px;
        opacity: 0;
        transition: opacity 0.2s ease;
      }

      .ant-menu-item:hover .menu-node-actions,
      .ant-menu-submenu-title:hover .menu-node-actions {
        opacity: 1;
      }

      .ant-menu-sub .ant-menu-item,
      .ant-menu-sub .ant-menu-submenu-title {
        min-height: ${theme.gridUnit * 7.5}px !important;
        height: ${theme.gridUnit * 7.5}px !important;
        line-height: ${theme.gridUnit * 7.5}px !important;
        margin-top: 1px !important;
        margin-bottom: 1px !important;
        padding-top: 0 !important;
        padding-bottom: 0 !important;
      }

      .menu-node-action {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        width: ${theme.gridUnit * 4}px;
        height: ${theme.gridUnit * 4}px;
        border-radius: ${theme.borderRadius}px;
        color: ${theme.colors.grayscale.dark1};

        &:hover {
          background-color: ${theme.colors.primary.light5};
          color: ${theme.colors.primary.base};
        }
      }

      .dashboard-default-item,
      .dashboard-folder-item {
        text-overflow: unset !important;
      }
  `}
`;

const globalStyles = (theme: SupersetTheme) => css``;
const { SubMenu } = DropdownMenu;

const { useBreakpoint } = Grid;

export function Menu({
  data: {
    menu,
    brand,
    navbar_right: navbarRight,
    settings,
    environment_tag: environmentTag,
  },
  isFrontendRoute = () => false,
}: MenuProps) {
  const [showMenu, setMenu] = useState<MenuMode>('inline');
  const initialLocationKeyRef = useRef<string | null>(null);
  const hasNavigatedFromInitialRouteRef = useRef(false);
  const [lastMenuSelectionKey, setLastMenuSelectionKey] = useState<string | null>(
    null,
  );
  const screens = useBreakpoint();
  const user = useSelector<any, Partial<UserWithPermissionsAndRoles>>(
    state => state.user || {},
  );
  const uiConfig = useUiConfig();
  const theme = useTheme();
  const history = useHistory();
  const { addDangerToast, addSuccessToast } = useToasts();
  const isTaggingEnabled = isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM);
  const [menuOpen, setMenuOpen] = useState(true);
  const [showCreateFolderModal, setShowCreateFolderModal] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [showCreateChartFolderModal, setShowCreateChartFolderModal] =
    useState(false);
  const [newChartFolderName, setNewChartFolderName] = useState('');
  const [renameFolderTarget, setRenameFolderTarget] = useState<DashboardFolder | null>(
    null,
  );
  const [renameFolderName, setRenameFolderName] = useState('');
  const [renameChartFolderTarget, setRenameChartFolderTarget] =
    useState<ChartFolder | null>(null);
  const [renameChartFolderName, setRenameChartFolderName] = useState('');
  const [deleteFolderTarget, setDeleteFolderTarget] = useState<DashboardFolder | null>(
    null,
  );
  const [deleteChartFolderTarget, setDeleteChartFolderTarget] =
    useState<ChartFolder | null>(null);
  const [createDashboardTarget, setCreateDashboardTarget] =
    useState<DashboardFolder | null>(null);
  const [newDashboardName, setNewDashboardName] = useState('');
  const { dashboardFolders, refreshDashboardFolders } = useDashboardFolders();
  const { chartFolders } = useChartFolders();
  const canManageDashboardFolders = Object.keys(user.roles || {}).some(
    role => role.toLowerCase() === ADMIN_ROLE_NAME,
  );

  useEffect(() => {
    function handleResize() {
      if (window.innerWidth <= 767) {
        setMenu('inline');
      } else setMenu('inline');
    }
    handleResize();
    const windowResize = debounce(() => handleResize(), 10);
    window.addEventListener('resize', windowResize);
    return () => window.removeEventListener('resize', windowResize);
  }, []);

  enum paths {
    EXPLORE = '/explore',
    DASHBOARD = '/dashboard',
    CHART = '/chart',
    DATASETS = '/tablemodelview',
  }

  const location = useLocation();

  if (!initialLocationKeyRef.current) {
    initialLocationKeyRef.current = `${location.pathname}${location.search}`;
  }

  useEffect(() => {
    const currentLocationKey = `${location.pathname}${location.search}`;

    if (currentLocationKey !== initialLocationKeyRef.current) {
      hasNavigatedFromInitialRouteRef.current = true;
    }
  }, [location.pathname, location.search]);

  const listQueryPrefix =
    'pageIndex=0&sortColumn=changed_on_delta_humanized&sortOrder=desc&viewMode=card';
  const favoritesFilter = `(favorite:(label:${t('Yes')},value:!t))`;
  const draftsFilter = `(published:(label:${t('Draft')},value:!f))`;

  const favoriteChartUrl = `/chart/list/?${listQueryPrefix}&filters=${favoritesFilter}`;
  const favoriteDashboardUrl =
    `/dashboard/list/?${listQueryPrefix}&filters=${favoritesFilter}`;
  const draftDashboardUrl =
    `/dashboard/list/?${listQueryPrefix}&filters=${draftsFilter}`;
  const allChartUrl = `/chart/list/?${listQueryPrefix}`;
  const allDashboardUrl = `/dashboard/list/?${listQueryPrefix}`;
  const getBrandPath = (path: string) => {
    const [pathname, search = ''] = path.split('?');

    if (normalizePath(pathname) !== normalizePath('/dashboard/list/')) {
      return path;
    }

    const searchParams = new URLSearchParams(search);
    searchParams.set('viewMode', 'card');

    return `${pathname}?${searchParams.toString()}`;
  };
  const brandPath = getBrandPath(brand.path);
  const getFolderDashboardUrl = (folderId: string) =>
    `/dashboard/list/?${listQueryPrefix}&${DASHBOARD_FOLDER_QUERY_KEY}=${encodeURIComponent(
      folderId,
    )}`;
  const getFolderChartUrl = (folderId: string) =>
    `/chart/list/?${listQueryPrefix}&${CHART_FOLDER_QUERY_KEY}=${encodeURIComponent(
      folderId,
    )}`;

  const navigateToFrontendRoute = (
    url: string,
    state?: { fromMenu?: boolean },
    menuSelectionKey?: string,
  ) => {
    const nextUrl = new URL(url, window.location.origin);
    const currentUrl = new URL(
      `${location.pathname}${location.search}`,
      window.location.origin,
    );

    if (
      nextUrl.pathname === currentUrl.pathname &&
      nextUrl.search === currentUrl.search
    ) {
      return;
    }

    if (menuSelectionKey) {
      setLastMenuSelectionKey(menuSelectionKey);
    }

    history.push(`${nextUrl.pathname}${nextUrl.search}`, state);
  };

  const onFrontendLinkClick = (
    event: React.MouseEvent<HTMLElement>,
    url?: string,
    state?: { fromMenu?: boolean },
    menuSelectionKey?: string,
  ) => {
    if (!url) {
      return;
    }
    event.preventDefault();
    navigateToFrontendRoute(url, state, menuSelectionKey);
  };

  const shouldSyncMenuStateFromRoute =
    !hasNavigatedFromInitialRouteRef.current ||
    Boolean((location.state as any)?.fromMenu);

  const matchesLastChartMenuSelection = useCallback(() => {
    if (!isChartMenuKey(lastMenuSelectionKey)) {
      return null;
    }

    const normalizedPath = normalizePath(location.pathname);
    const normalizedChartPath = normalizePath('/chart/list/');
    const searchParams = new URLSearchParams(location.search);
    const filters = searchParams.get('filters');
    const folderId = searchParams.get(CHART_FOLDER_QUERY_KEY);
    const sliceId = searchParams.get('slice_id');

    if (lastMenuSelectionKey === CHARTS_ROOT_KEY) {
      return normalizedPath === normalizedChartPath &&
        getChartListKeyFromFilters(filters) === CHARTS_ROOT_KEY &&
        !folderId
        ? lastMenuSelectionKey
        : null;
    }

    if (lastMenuSelectionKey === CHART_FAVORITES_KEY) {
      return normalizedPath === normalizedChartPath &&
        getChartListKeyFromFilters(filters) === CHART_FAVORITES_KEY
        ? lastMenuSelectionKey
        : null;
    }

    if (isChartFolderMenuKey(lastMenuSelectionKey)) {
      return normalizedPath === normalizedChartPath &&
        folderId &&
        getChartFolderMenuKey(folderId) === lastMenuSelectionKey
        ? lastMenuSelectionKey
        : null;
    }

    if (isChartFolderItemMenuKey(lastMenuSelectionKey)) {
      const matchedItem = chartFolders
        .flatMap(folder => folder.items)
        .find(item => getChartFolderItemMenuKey(item.id) === lastMenuSelectionKey);

      return normalizedPath === normalizePath('/explore/') &&
        matchedItem &&
        `${matchedItem.chartId}` === sliceId
        ? lastMenuSelectionKey
        : null;
    }

    return null;
  }, [chartFolders, lastMenuSelectionKey, location.pathname, location.search]);

  const matchesLastDashboardMenuSelection = useCallback(() => {
    if (!isDashboardMenuKey(lastMenuSelectionKey)) {
      return null;
    }

    const normalizedPath = normalizePath(location.pathname);
    const normalizedDashboardPath = normalizePath('/dashboard/list/');
    const searchParams = new URLSearchParams(location.search);
    const filters = searchParams.get('filters');
    const folderId = searchParams.get(DASHBOARD_FOLDER_QUERY_KEY);

    if (lastMenuSelectionKey === DASHBOARDS_ROOT_KEY) {
      return normalizedPath === normalizedDashboardPath &&
        getDashboardListKeyFromFilters(filters) === DASHBOARDS_ROOT_KEY &&
        !folderId
        ? lastMenuSelectionKey
        : null;
    }

    if (lastMenuSelectionKey === DASHBOARD_FAVORITES_KEY) {
      return normalizedPath === normalizedDashboardPath &&
        getDashboardListKeyFromFilters(filters) === DASHBOARD_FAVORITES_KEY
        ? lastMenuSelectionKey
        : null;
    }

    if (lastMenuSelectionKey === DASHBOARD_DRAFTS_KEY) {
      return normalizedPath === normalizedDashboardPath &&
        getDashboardListKeyFromFilters(filters) === DASHBOARD_DRAFTS_KEY
        ? lastMenuSelectionKey
        : null;
    }

    if (isDashboardFolderMenuKey(lastMenuSelectionKey)) {
      return normalizedPath === normalizedDashboardPath &&
        folderId &&
        getDashboardFolderMenuKey(folderId) === lastMenuSelectionKey
        ? lastMenuSelectionKey
        : null;
    }

    if (isDashboardFolderItemMenuKey(lastMenuSelectionKey)) {
      const matchedItem = dashboardFolders
        .flatMap(folder => folder.items)
        .find(
          item =>
            getDashboardFolderItemMenuKey(item.id) === lastMenuSelectionKey,
        );

      return normalizedPath.startsWith('/superset/dashboard/') &&
        matchedItem &&
        normalizePath(matchedItem.url) === normalizedPath
        ? lastMenuSelectionKey
        : null;
    }

    return null;
  }, [dashboardFolders, lastMenuSelectionKey, location.pathname, location.search]);

  const getChartSelection = () => {
    const retainedSelection = matchesLastChartMenuSelection();
    if (retainedSelection) {
      return retainedSelection;
    }

    const normalizedPath = normalizePath(location.pathname);
    const normalizedChartPath = normalizePath('/chart/list/');
    const searchParams = new URLSearchParams(location.search);
    const filters = searchParams.get('filters');
    const folderId = searchParams.get(CHART_FOLDER_QUERY_KEY);
    const sliceId = searchParams.get('slice_id');

    if (normalizedPath === normalizedChartPath) {
      if (
        folderId &&
        chartFolders.some(folder => String(folder.id) === folderId)
      ) {
        return getChartFolderMenuKey(folderId);
      }

      return getChartListKeyFromFilters(filters);
    }

    if (normalizedPath === normalizePath('/explore/')) {
      if (!shouldSyncMenuStateFromRoute) {
        return null;
      }

      const folderItem = chartFolders
        .flatMap(folder => folder.items)
        .find(item => `${item.chartId}` === sliceId);

      if (folderItem) {
        return getChartFolderItemMenuKey(folderItem.id);
      }

      return null;
    }

    return null;
  };

  const getDashboardSelection = () => {
    const retainedSelection = matchesLastDashboardMenuSelection();
    if (retainedSelection) {
      return retainedSelection;
    }

    const normalizedPath = normalizePath(location.pathname);
    const normalizedFavoritePath = normalizePath('/dashboard/list/');
    const searchParams = new URLSearchParams(location.search);
    const filters = searchParams.get('filters');
    const folderId = searchParams.get(DASHBOARD_FOLDER_QUERY_KEY);

    if (normalizedPath === normalizedFavoritePath) {
      if (
        folderId &&
        dashboardFolders.some(folder => String(folder.id) === folderId)
      ) {
        return getDashboardFolderMenuKey(folderId);
      }

      return getDashboardListKeyFromFilters(filters);
    }

    if (normalizedPath.startsWith('/superset/dashboard/')) {
      if (!shouldSyncMenuStateFromRoute) {
        return null;
      }

      const dashboardIdOrSlug = normalizedPath.split('/').pop();
      const folderItem = dashboardFolders
        .flatMap(folder => folder.items)
        .find(
          item =>
            `${item.dashboardId}` === dashboardIdOrSlug ||
            normalizePath(item.url) === normalizedPath,
        );

      if (folderItem) {
        return getDashboardFolderItemMenuKey(folderItem.id);
      }

      return null;
    }

    return null;
  };

  const getGenericOpenKeys = useCallback(() => {
    const currentPath = normalizePath(location.pathname);

    const findChildOpenKeys = (
      children: Array<MenuObjectChildProps | string>,
      ancestorKeys: string[],
    ): string[] | null =>
      children.reduce<string[] | null>((match, child) => {
        if (match || typeof child === 'string') {
          return match;
        }

        const childNode = child as MenuObjectProps;
        const childPath = getPathnameFromUrl(childNode.url);

        if (childPath && childPath === currentPath) {
          return childNode.childs?.length
            ? [...ancestorKeys, childNode.label]
            : ancestorKeys;
        }

        if (!childNode.childs?.length) {
          return null;
        }

        return findChildOpenKeys(childNode.childs, [
          ...ancestorKeys,
          childNode.label,
        ]);
      }, null);

    const genericMatch = menu.reduce<string[] | null>((match, item, fallbackIndex) => {
      if (match) {
        return match;
      }

      if (item.name === CHARTS_ROOT_KEY || item.name === DASHBOARDS_ROOT_KEY) {
        return null;
      }

      const topLevelKey = String(item.index ?? fallbackIndex);
      const itemPath = getPathnameFromUrl(item.url);

      if (itemPath && itemPath === currentPath) {
        return [topLevelKey];
      }

      if (!item.childs?.length) {
        return null;
      }

      return findChildOpenKeys(item.childs, [topLevelKey]);
    }, null);

    if (genericMatch) {
      return genericMatch;
    }

    return [] as string[];
  }, [location.pathname, menu]);

  const activeMenuKeys = useMemo(() => {
    const chartSelection = getChartSelection();
    if (chartSelection) {
      if (isChartFolderMenuKey(chartSelection)) {
        return [];
      }

      return [chartSelection];
    }

    const dashboardSelection = getDashboardSelection();
    if (dashboardSelection) {
      if (isDashboardFolderMenuKey(dashboardSelection)) {
        return [];
      }

      return [dashboardSelection];
    }

    const path = location.pathname;
    switch (true) {
      case path.startsWith(paths.CHART):
        return ['Charts'];
      case path.startsWith(paths.DATASETS):
        return ['Datasets'];
      default:
        return [];
    }
  }, [
    chartFolders,
    dashboardFolders,
    draftsFilter,
    favoritesFilter,
    location.pathname,
    location.search,
  ]);

  const chartSelection = useMemo(
    () => getChartSelection(),
    [chartFolders, location.pathname, location.search],
  );
  const dashboardSelection = useMemo(
    () => getDashboardSelection(),
    [dashboardFolders, location.pathname, location.search],
  );
  const isChartListRoute =
    normalizePath(location.pathname) === normalizePath('/chart/list/');
  const isDashboardListRoute =
    normalizePath(location.pathname) === normalizePath('/dashboard/list/');
  const hasChartFavoriteFilter = location.search.includes('favorite');
  const hasFavoriteFilter = location.search.includes('favorite');
  const hasDraftFilter = location.search.includes('published');

  const defaultOpenKeys = useMemo(() => {
    const currentChartKey = getChartSelection();
    const currentChartFolder = chartFolders.find(folder =>
      getChartFolderMenuKey(folder.id) === currentChartKey ||
      folder.items.some(item => getChartFolderItemMenuKey(item.id) === currentChartKey),
    );
    const currentKey = getDashboardSelection();
    const currentFolder = dashboardFolders.find(folder =>
      getDashboardFolderMenuKey(folder.id) === currentKey ||
      folder.items.some(
        item => getDashboardFolderItemMenuKey(item.id) === currentKey,
      ),
    );

    if (currentChartKey) {
      return [
        CHARTS_ROOT_KEY,
        currentChartFolder ? getChartFolderMenuKey(currentChartFolder.id) : null,
      ].filter(Boolean) as string[];
    }

    if (currentKey) {
      return [
        DASHBOARDS_ROOT_KEY,
        currentFolder ? getDashboardFolderMenuKey(currentFolder.id) : null,
      ].filter(Boolean) as string[];
    }

    return getGenericOpenKeys();
  }, [
    chartFolders,
    dashboardFolders,
    getGenericOpenKeys,
    location.pathname,
    location.search,
  ]);

  const topLevelSubmenuKeys = useMemo(
    () =>
      menu.flatMap((item, fallbackIndex) => {
        if (item.name === CHARTS_ROOT_KEY) {
          return [CHARTS_ROOT_KEY];
        }

        if (item.name === DASHBOARDS_ROOT_KEY) {
          return [DASHBOARDS_ROOT_KEY];
        }

        if (item.childs?.length) {
          return [String(item.index ?? fallbackIndex)];
        }

        return [];
      }),
    [menu],
  );

  const [openKeys, setOpenKeys] = useState<string[]>(defaultOpenKeys);

  useEffect(() => {
    if (shouldSyncMenuStateFromRoute) {
      setOpenKeys(defaultOpenKeys);
    }
  }, [defaultOpenKeys, shouldSyncMenuStateFromRoute]);

  const handleSubMenuTitleClick = useCallback(
    (_menuKey: string, url?: string) =>
      (info: any) => {
        const target = info?.domEvent?.target as HTMLElement | null;

        if (target?.closest('.menu-node-action')) {
          return;
        }

        if (url) {
          navigateToFrontendRoute(url, { fromMenu: true }, _menuKey);
        }
      },
    [navigateToFrontendRoute],
  );

  const handleOpenKeysChange = useCallback(
    (keys: string[]) => {
      const latestOpenedKey = keys.find(key => !openKeys.includes(key));

      if (!latestOpenedKey) {
        setOpenKeys(keys);
        return;
      }

      if (latestOpenedKey === CHARTS_ROOT_KEY) {
        setOpenKeys(
          keys.filter(
            key => key === CHARTS_ROOT_KEY || isChartFolderMenuKey(key),
          ),
        );
        return;
      }

      if (latestOpenedKey === DASHBOARDS_ROOT_KEY) {
        setOpenKeys(
          keys.filter(
            key => key === DASHBOARDS_ROOT_KEY || isDashboardFolderMenuKey(key),
          ),
        );
        return;
      }

      if (isChartFolderMenuKey(latestOpenedKey)) {
        setOpenKeys(
          keys.filter(
            key =>
              key === CHARTS_ROOT_KEY ||
              key === latestOpenedKey ||
              (!isChartFolderMenuKey(key) && !isDashboardFolderMenuKey(key)),
          ),
        );
        return;
      }

      if (isDashboardFolderMenuKey(latestOpenedKey)) {
        setOpenKeys(
          keys.filter(
            key =>
              key === DASHBOARDS_ROOT_KEY ||
              key === latestOpenedKey ||
              (!isChartFolderMenuKey(key) && !isDashboardFolderMenuKey(key)),
          ),
        );
        return;
      }

      if (topLevelSubmenuKeys.includes(latestOpenedKey)) {
        setOpenKeys(
          keys.filter(
            key =>
              key === latestOpenedKey || !topLevelSubmenuKeys.includes(key),
          ),
        );
        return;
      }

      setOpenKeys(keys);
    },
    [openKeys, topLevelSubmenuKeys],
  );

  const standalone = getUrlParam(URL_PARAMS.standalone);
  if (standalone || uiConfig.hideNav) return <></>;

  const renderActionButton = ({
    label,
    icon,
    onClick,
  }: {
    label: string;
    icon: React.ReactNode;
    onClick: (event: React.MouseEvent<HTMLSpanElement>) => void;
  }) => (
    <Tooltip id={label} key={label} title={label} placement="top">
      <span
        aria-label={label}
        className="menu-node-action"
        onClick={onClick}
        onKeyDown={() => undefined}
        role="button"
        tabIndex={0}
      >
        {icon}
      </span>
    </Tooltip>
  );

  const renderMenuNodeContent = ({
    label,
    actions,
    onClick,
    className,
  }: {
    label: React.ReactNode;
    actions?: React.ReactNode[];
    onClick?: (event: React.MouseEvent<HTMLButtonElement>) => void;
    className?: string;
  }) => {
    const content = (
      <span className="menu-node-label">
        <span className="menu-node-label-text">{label}</span>
      </span>
    );

    const actionNodes = actions?.length ? (
      <span className="menu-node-actions">{actions}</span>
    ) : null;

    if (onClick) {
      return (
        <button
          type="button"
          className={`menu-node-content${className ? ` ${className}` : ''}`}
          onClick={onClick}
        >
          {content}
          {actionNodes}
        </button>
      );
    }

    return (
      <div className={`menu-node-content${className ? ` ${className}` : ''}`}>
        {content}
        {actionNodes}
      </div>
    );
  };

  const addFolder = async () => {
    if (!canManageDashboardFolders) {
      return;
    }

    const folderName = newFolderName.trim();
    if (!folderName) {
      return;
    }

    try {
      await createDashboardFolder(folderName);
      setShowCreateFolderModal(false);
      setNewFolderName('');
      addSuccessToast(t('文件夹已创建'));
    } catch {
      addDangerToast(t('创建文件夹失败'));
    }
  };

  const openCreateFolderModal = () => {
    if (!canManageDashboardFolders) {
      return;
    }

    setNewFolderName('');
    setShowCreateFolderModal(true);
  };

  const closeCreateFolderModal = () => {
    setShowCreateFolderModal(false);
    setNewFolderName('');
  };

  const addChartFolder = async () => {
    if (!canManageDashboardFolders) {
      return;
    }

    const folderName = newChartFolderName.trim();
    if (!folderName) {
      return;
    }

    try {
      await createChartFolder(folderName);
      setShowCreateChartFolderModal(false);
      setNewChartFolderName('');
      addSuccessToast(t('分类已创建'));
    } catch {
      addDangerToast(t('创建分类失败'));
    }
  };

  const openCreateChartFolderModal = () => {
    if (!canManageDashboardFolders) {
      return;
    }

    setNewChartFolderName('');
    setShowCreateChartFolderModal(true);
  };

  const closeCreateChartFolderModal = () => {
    setShowCreateChartFolderModal(false);
    setNewChartFolderName('');
  };

  const addDashboardFolderTag = async (dashboardId: number, folderName: string) => {
    if (!isTaggingEnabled || !folderName.trim()) {
      return;
    }

    await new Promise<void>((resolve, reject) => {
      addTag(
        {
          objectType: OBJECT_TYPES.DASHBOARD,
          objectId: dashboardId,
          includeTypes: false,
        },
        folderName,
        () => resolve(),
        response => reject(response),
      );
    });
  };

  const deleteDashboardFolderTag = async (
    dashboardId: number,
    folderName: string,
  ) => {
    if (!isTaggingEnabled || !folderName.trim()) {
      return;
    }

    await new Promise<void>((resolve, reject) => {
      deleteTaggedObjects(
        {
          objectType: OBJECT_TYPES.DASHBOARD,
          objectId: dashboardId,
        },
        { name: folderName } as TagType,
        () => resolve(),
        errorText => reject(new Error(errorText)),
      );
    });
  };

  const syncFolderTags = async ({
    items,
    previousName,
    nextName,
  }: {
    items: DashboardFolderItem[];
    previousName?: string;
    nextName?: string;
  }) => {
    if (!isTaggingEnabled || !items.length) {
      return true;
    }

    const results = await Promise.allSettled(
      items.map(async item => {
        if (previousName && previousName !== nextName) {
          await deleteDashboardFolderTag(item.dashboardId, previousName);
        }

        if (nextName && previousName !== nextName) {
          await addDashboardFolderTag(item.dashboardId, nextName);
        }
      }),
    );

    return results.every(result => result.status === 'fulfilled');
  };

  const openRenameFolderModal = (folderId: string) => {
    if (!canManageDashboardFolders) {
      return;
    }

    const folder = dashboardFolders.find(item => item.id === folderId);
    if (!folder) {
      return;
    }

    setRenameFolderTarget(folder);
    setRenameFolderName(folder.name);
  };

  const closeRenameFolderModal = () => {
    setRenameFolderTarget(null);
    setRenameFolderName('');
  };

  const openRenameChartFolderModal = (folderId: string) => {
    if (!canManageDashboardFolders) {
      return;
    }

    const folder = chartFolders.find(item => item.id === folderId);
    if (!folder) {
      return;
    }

    setRenameChartFolderTarget(folder);
    setRenameChartFolderName(folder.name);
  };

  const closeRenameChartFolderModal = () => {
    setRenameChartFolderTarget(null);
    setRenameChartFolderName('');
  };

  const renameFolder = async () => {
    if (!canManageDashboardFolders || !renameFolderTarget) {
      return;
    }

    const folderName = renameFolderName.trim();
    if (!folderName) {
      return;
    }

    try {
      await renameDashboardFolder(renameFolderTarget.id, folderName);
      const tagsUpdated = await syncFolderTags({
        items: renameFolderTarget.items,
        previousName: renameFolderTarget.name,
        nextName: folderName,
      });
      closeRenameFolderModal();
      if (tagsUpdated) {
        addSuccessToast(t('分类已重命名'));
      } else {
        addDangerToast(t('分类已重命名，但部分仪表盘标签同步失败'));
      }
    } catch {
      addDangerToast(t('重命名分类失败'));
    }
  };

  const renameChartFolder = async () => {
    if (!canManageDashboardFolders || !renameChartFolderTarget) {
      return;
    }

    const folderName = renameChartFolderName.trim();
    if (!folderName) {
      return;
    }

    try {
      await renameChartFolderApi(renameChartFolderTarget.id, folderName);
      closeRenameChartFolderModal();
      addSuccessToast(t('分类已重命名'));
    } catch {
      addDangerToast(t('重命名分类失败'));
    }
  };

  const openDeleteFolderModal = (folderId: string) => {
    if (!canManageDashboardFolders) {
      return;
    }

    const folder = dashboardFolders.find(item => item.id === folderId);
    if (!folder) {
      return;
    }

    setDeleteFolderTarget(folder);
  };

  const closeDeleteFolderModal = () => {
    setDeleteFolderTarget(null);
  };

  const openDeleteChartFolderModal = (folderId: string) => {
    if (!canManageDashboardFolders) {
      return;
    }

    const folder = chartFolders.find(item => item.id === folderId);
    if (!folder) {
      return;
    }

    setDeleteChartFolderTarget(folder);
  };

  const closeDeleteChartFolderModal = () => {
    setDeleteChartFolderTarget(null);
  };

  const deleteFolder = async () => {
    if (!canManageDashboardFolders || !deleteFolderTarget) {
      return;
    }

    try {
      await deleteDashboardFolder(deleteFolderTarget.id);
      const tagsUpdated = await syncFolderTags({
        items: deleteFolderTarget.items,
        previousName: deleteFolderTarget.name,
      });
      closeDeleteFolderModal();
      if (tagsUpdated) {
        addSuccessToast(t('分类已删除'));
      } else {
        addDangerToast(t('分类已删除，但部分仪表盘标签移除失败'));
      }
    } catch {
      addDangerToast(t('删除分类失败'));
    }
  };

  const deleteChartFolderHandler = async () => {
    if (!canManageDashboardFolders || !deleteChartFolderTarget) {
      return;
    }

    try {
      await deleteChartFolder(deleteChartFolderTarget.id);
      closeDeleteChartFolderModal();
      addSuccessToast(t('分类已删除'));
    } catch {
      addDangerToast(t('删除分类失败'));
    }
  };

  const openCreateDashboardModal = (folderId: string) => {
    const folder = dashboardFolders.find(item => item.id === folderId);
    if (!folder) {
      return;
    }

    setCreateDashboardTarget(folder);
    setNewDashboardName('');
  };

  const closeCreateDashboardModal = () => {
    setCreateDashboardTarget(null);
    setNewDashboardName('');
  };

  const createDashboardInFolder = async () => {
    if (!createDashboardTarget) {
      return;
    }

    const dashboardName = newDashboardName.trim();
    if (!dashboardName) {
      return;
    }

    try {
      const { json } = await SupersetClient.post({
        endpoint: '/api/v1/dashboard/',
        jsonPayload: { dashboard_title: dashboardName },
      });
      const dashboard = json?.result || {};
      const dashboardId = json?.id || dashboard?.id;

      if (!dashboardId) {
        throw new Error('dashboard id not found');
      }

      const newItem: DashboardFolderItem = {
        id: String(dashboardId),
        dashboardId,
        name: dashboard?.dashboard_title || dashboardName,
        url: normalizeDashboardUrl(dashboard?.url, dashboardId),
      };

      await addDashboardToFolder(createDashboardTarget.id, dashboardId);

      let tagSynchronized = true;
      if (createDashboardTarget.name.trim()) {
        try {
          await addDashboardFolderTag(dashboardId, createDashboardTarget.name.trim());
        } catch {
          tagSynchronized = false;
        }
      }

      await refreshDashboardFolders();

      closeCreateDashboardModal();
      if (tagSynchronized) {
        addSuccessToast(t('仪表盘已创建'));
      } else {
        addDangerToast(t('仪表盘已创建，但文件夹标签同步失败'));
      }
      window.location.href = newItem.url;
    } catch {
      addDangerToast(t('创建仪表盘失败'));
    }
  };

  const renderSubMenu = ({
    name,
    label,
    childs,
    url,
    index,
    isFrontendRoute,
  }: MenuObjectProps) => {
    const icon = iconMap[name || ''] || <FileOutlined />;
    const isChartRootSelected =
      chartSelection === CHARTS_ROOT_KEY &&
      (!isChartListRoute || !hasChartFavoriteFilter);
    const isChartFavoriteSelected = isChartListRoute && hasChartFavoriteFilter;
    const isDashboardRootSelected =
      dashboardSelection === DASHBOARDS_ROOT_KEY &&
      (!isDashboardListRoute || (!hasFavoriteFilter && !hasDraftFilter));
    const isFavoriteSelected = isDashboardListRoute && hasFavoriteFilter;
    const isDraftSelected = isDashboardListRoute && hasDraftFilter;

    if (name === CHARTS_ROOT_KEY) {
      const chartRootActions = canManageDashboardFolders
        ? [
            renderActionButton({
              label: t('新建分类'),
              icon: <PlusOutlined />,
              onClick: event => {
                event.preventDefault();
                event.stopPropagation();
                openCreateChartFolderModal();
              },
            }),
          ]
        : undefined;

      return (
        <SubMenu
          key={CHARTS_ROOT_KEY}
          popupClassName="dashboard-menu-root"
          className={isChartRootSelected ? 'menu-submenu-manual-selected' : ''}
          title={renderMenuNodeContent({
            label,
            className: isChartRootSelected ? 'menu-submenu-manual-selected' : undefined,
            actions: chartRootActions,
          })}
          icon={icon}
          onTitleClick={handleSubMenuTitleClick(CHARTS_ROOT_KEY, allChartUrl)}
        >
          <DropdownMenu.Item
            key={CHART_FAVORITES_KEY}
            icon={<StarOutlined />}
            className={`dashboard-default-item${
              isChartFavoriteSelected ? ' menu-item-manual-selected' : ''
            }`}
          >
            <a
              className={isChartFavoriteSelected ? 'menu-link-manual-selected' : ''}
              href={favoriteChartUrl}
              onClick={event =>
                onFrontendLinkClick(
                  event,
                  favoriteChartUrl,
                  { fromMenu: true },
                  CHART_FAVORITES_KEY,
                )
              }
            >
              {t('我的收藏')}
            </a>
          </DropdownMenu.Item>
          {chartFolders.map(folder => (
            <SubMenu
              key={getChartFolderMenuKey(folder.id)}
              popupClassName="dashboard-menu-root"
              className={`dashboard-folder-submenu${
                chartSelection === getChartFolderMenuKey(folder.id)
                  ? ' menu-submenu-manual-selected'
                  : ''
              }`}
              title={renderMenuNodeContent({
                label: folder.name,
                className:
                  chartSelection === getChartFolderMenuKey(folder.id)
                    ? 'menu-submenu-manual-selected'
                    : undefined,
                actions: canManageDashboardFolders
                  ? [
                      renderActionButton({
                        label: t('重命名分类'),
                        icon: <EditOutlined />,
                        onClick: event => {
                          event.preventDefault();
                          event.stopPropagation();
                          openRenameChartFolderModal(folder.id);
                        },
                      }),
                      renderActionButton({
                        label: t('删除分类'),
                        icon: <DeleteOutlined />,
                        onClick: event => {
                          event.preventDefault();
                          event.stopPropagation();
                          openDeleteChartFolderModal(folder.id);
                        },
                      }),
                    ]
                  : undefined,
              })}
              icon={<FolderOutlined />}
              onTitleClick={handleSubMenuTitleClick(
                getChartFolderMenuKey(folder.id),
                getFolderChartUrl(folder.id),
              )}
            >
              {folder.items.map(item => {
                const chartUrl = normalizeChartUrl(item.url, item.chartId);

                return (
                  <DropdownMenu.Item
                    key={getChartFolderItemMenuKey(item.id)}
                    className="dashboard-folder-item"
                    icon={
                      <DashboardMenuItemIcon
                        src="/static/assets/images/chart-list-icon.svg"
                        alt=""
                      />
                    }
                  >
                    {renderMenuNodeContent({
                      label: (
                        <a
                          href={chartUrl}
                          onClick={event =>
                            onFrontendLinkClick(event, chartUrl, {
                              fromMenu: true,
                            }, getChartFolderItemMenuKey(item.id))
                          }
                        >
                          {item.name}
                        </a>
                      ),
                    })}
                  </DropdownMenu.Item>
                );
              })}
            </SubMenu>
          ))}
        </SubMenu>
      );
    }

    if (name === DASHBOARDS_ROOT_KEY) {
      const dashboardRootActions = canManageDashboardFolders
        ? [
            renderActionButton({
              label: t('新建分类'),
              icon: <PlusOutlined />,
              onClick: event => {
                event.preventDefault();
                event.stopPropagation();
                openCreateFolderModal();
              },
            }),
          ]
        : undefined;

      return (
        <SubMenu
          key={DASHBOARDS_ROOT_KEY}
          popupClassName="dashboard-menu-root"
          className={isDashboardRootSelected ? 'menu-submenu-manual-selected' : ''}
          title={renderMenuNodeContent({
            label,
            className: isDashboardRootSelected
              ? 'menu-submenu-manual-selected'
              : undefined,
            actions: dashboardRootActions,
          })}
          icon={icon}
          onTitleClick={handleSubMenuTitleClick(
            DASHBOARDS_ROOT_KEY,
            allDashboardUrl,
          )}
        >
          <DropdownMenu.Item
            key={DASHBOARD_FAVORITES_KEY}
            icon={<StarOutlined />}
            className={`dashboard-default-item${
              isFavoriteSelected ? ' menu-item-manual-selected' : ''
            }`}
          >
            <a
              className={isFavoriteSelected ? 'menu-link-manual-selected' : ''}
              href={favoriteDashboardUrl}
              onClick={event =>
                onFrontendLinkClick(event, favoriteDashboardUrl, {
                  fromMenu: true,
                }, DASHBOARD_FAVORITES_KEY)
              }
            >
              {t('我的收藏')}
            </a>
          </DropdownMenu.Item>
          <DropdownMenu.Item
            key={DASHBOARD_DRAFTS_KEY}
            icon={<FileTextOutlined />}
            className={`dashboard-default-item${
              isDraftSelected ? ' menu-item-manual-selected' : ''
            }`}
          >
            <a
              className={isDraftSelected ? 'menu-link-manual-selected' : ''}
              href={draftDashboardUrl}
              onClick={event =>
                onFrontendLinkClick(event, draftDashboardUrl, {
                  fromMenu: true,
                }, DASHBOARD_DRAFTS_KEY)
              }
            >
              {t('我的草稿')}
            </a>
          </DropdownMenu.Item>
          {dashboardFolders.map(folder => (
            <SubMenu
              key={getDashboardFolderMenuKey(folder.id)}
              popupClassName="dashboard-menu-root"
              className={`dashboard-folder-submenu${
                dashboardSelection === getDashboardFolderMenuKey(folder.id)
                  ? ' menu-submenu-manual-selected'
                  : ''
              }`}
              title={renderMenuNodeContent({
                label: folder.name,
                className:
                  dashboardSelection === getDashboardFolderMenuKey(folder.id)
                    ? 'menu-submenu-manual-selected'
                    : undefined,
                actions: [
                  renderActionButton({
                    label: t('新建仪表盘'),
                    icon: <PlusOutlined />,
                    onClick: event => {
                      event.preventDefault();
                      event.stopPropagation();
                      openCreateDashboardModal(folder.id);
                    },
                  }),
                  ...(canManageDashboardFolders
                    ? [
                        renderActionButton({
                          label: t('重命名分类'),
                          icon: <EditOutlined />,
                          onClick: event => {
                            event.preventDefault();
                            event.stopPropagation();
                            openRenameFolderModal(folder.id);
                          },
                        }),
                        renderActionButton({
                          label: t('删除分类'),
                          icon: <DeleteOutlined />,
                          onClick: event => {
                            event.preventDefault();
                            event.stopPropagation();
                            openDeleteFolderModal(folder.id);
                          },
                        }),
                      ]
                    : []),
                ],
              })}
              icon={<FolderOutlined />}
              onTitleClick={handleSubMenuTitleClick(
                getDashboardFolderMenuKey(folder.id),
                getFolderDashboardUrl(folder.id),
              )}
            >
              {folder.items.map(item => (
                <DropdownMenu.Item
                  key={getDashboardFolderItemMenuKey(item.id)}
                  className="dashboard-folder-item"
                  icon={
                    <DashboardMenuItemIcon
                      src="/static/assets/images/dashboard-list-icon.svg"
                      alt=""
                    />
                  }
                >
                  {renderMenuNodeContent({
                    label: (
                      <a
                        href={item.url}
                        onClick={event =>
                          onFrontendLinkClick(event, item.url, {
                            fromMenu: true,
                          }, getDashboardFolderItemMenuKey(item.id))
                        }
                      >
                        {item.name}
                      </a>
                    ),
                  })}
                </DropdownMenu.Item>
              ))}
            </SubMenu>
          ))}
        </SubMenu>
      );
    }

    if (url && isFrontendRoute) {
      return (
        <DropdownMenu.Item key={label} role="presentation" icon={icon}>
          <NavLink
            role="button"
            to={url}
            activeClassName="is-active"
            onClick={event => onFrontendLinkClick(event, url, { fromMenu: true })}
          >
            {label}
          </NavLink>
        </DropdownMenu.Item>
      );
    }
    if (url) {
      return (
        <DropdownMenu.Item key={label} icon={icon}>
          <a href={url}>{label}</a>
        </DropdownMenu.Item>
      );
    }

    const renderChild = (child: MenuObjectChildProps | string, idx: number) => {
      if (typeof child === 'string') {
        if (child === '-' && label !== 'Data') {
          return <DropdownMenu.Divider key={`divider-${idx}`} />;
        }
        return null;
      }

      const childObj = child as MenuObjectProps;
      const hasChildren = childObj.childs && childObj.childs.length > 0;

      if (hasChildren) {
        return (
          <SubMenu
            key={child.label}
            title={child.label}
            icon={<FolderOutlined />}
          >
            {childObj.childs?.map((grandChild, grandIdx) =>
              renderChild(grandChild, grandIdx),
            )}
          </SubMenu>
        );
      }

      return (
        <DropdownMenu.Item key={child.label} icon={<FileOutlined />}>
          {child.isFrontendRoute ? (
            <NavLink
              to={child.url || ''}
              exact
              activeClassName="is-active"
              onClick={event =>
                onFrontendLinkClick(event, child.url, { fromMenu: true })
              }
            >
              {child.label}
            </NavLink>
          ) : (
            <a href={child.url}>{child.label}</a>
          )}
        </DropdownMenu.Item>
      );
    };

    return (
      <SubMenu key={String(index)} title={label} icon={icon}>
        {childs?.map((child, index1) => renderChild(child, index1))}
      </SubMenu>
    );
  };

  return (
    <>
      <Modal
        show={showCreateChartFolderModal}
        onHide={closeCreateChartFolderModal}
        onHandledPrimaryAction={addChartFolder}
        primaryButtonName={t('创建')}
        disablePrimaryButton={!newChartFolderName.trim()}
        title={<h4>{t('新建分类')}</h4>}
      >
        <Input
          autoFocus
          value={newChartFolderName}
          placeholder={t('请输入分类名称')}
          onChange={event => setNewChartFolderName(event.target.value)}
          onPressEnter={addChartFolder}
        />
      </Modal>
      <Modal
        show={showCreateFolderModal}
        onHide={closeCreateFolderModal}
        onHandledPrimaryAction={addFolder}
        primaryButtonName={t('创建')}
        disablePrimaryButton={!newFolderName.trim()}
        title={<h4>{t('新建分类')}</h4>}
      >
        <Input
          autoFocus
          value={newFolderName}
          placeholder={t('请输入文件夹名称')}
          onChange={event => setNewFolderName(event.target.value)}
          onPressEnter={addFolder}
        />
      </Modal>
      <Modal
        show={!!createDashboardTarget}
        onHide={closeCreateDashboardModal}
        onHandledPrimaryAction={createDashboardInFolder}
        primaryButtonName={t('创建')}
        disablePrimaryButton={!newDashboardName.trim()}
        title={<h4>{t('新建仪表盘')}</h4>}
      >
        <Input
          autoFocus
          value={newDashboardName}
          placeholder={t('请输入仪表盘名称')}
          onChange={event => setNewDashboardName(event.target.value)}
          onPressEnter={createDashboardInFolder}
        />
      </Modal>
      <Modal
        show={!!renameChartFolderTarget}
        onHide={closeRenameChartFolderModal}
        onHandledPrimaryAction={renameChartFolder}
        primaryButtonName={t('保存')}
        disablePrimaryButton={!renameChartFolderName.trim()}
        title={<h4>{t('重命名分类')}</h4>}
      >
        <Input
          autoFocus
          value={renameChartFolderName}
          placeholder={t('请输入新的分类名称')}
          onChange={event => setRenameChartFolderName(event.target.value)}
          onPressEnter={renameChartFolder}
        />
      </Modal>
      <Modal
        show={!!renameFolderTarget}
        onHide={closeRenameFolderModal}
        onHandledPrimaryAction={renameFolder}
        primaryButtonName={t('保存')}
        disablePrimaryButton={!renameFolderName.trim()}
        title={<h4>{t('重命名分类')}</h4>}
      >
        <Input
          autoFocus
          value={renameFolderName}
          placeholder={t('请输入新的分类名称')}
          onChange={event => setRenameFolderName(event.target.value)}
          onPressEnter={renameFolder}
        />
      </Modal>
      <Modal
        show={!!deleteChartFolderTarget}
        onHide={closeDeleteChartFolderModal}
        onHandledPrimaryAction={deleteChartFolderHandler}
        primaryButtonName={t('删除')}
        primaryButtonType="danger"
        title={<h4>{t('删除分类')}</h4>}
      >
        <div>
          {deleteChartFolderTarget?.items.length
            ? t('删除分类仅会移除左侧菜单快捷方式，不会删除其中的图表。是否继续？')
            : t('确认删除该分类吗？')}
        </div>
      </Modal>
      <Modal
        show={!!deleteFolderTarget}
        onHide={closeDeleteFolderModal}
        onHandledPrimaryAction={deleteFolder}
        primaryButtonName={t('删除')}
        primaryButtonType="danger"
        title={<h4>{t('删除分类')}</h4>}
      >
        <div>
          {deleteFolderTarget?.items.length
            ? t(
                '删除分类仅会移除左侧菜单快捷方式，不会删除其中的仪表盘。是否继续？',
              )
            : t('确认删除该分类吗？')}
        </div>
      </Modal>
      <StyledHeader className="top" id="main-menu" role="navigation">
        <Global styles={globalStyles(theme)} />
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            height: '100%',
          }}
        >
          <div className="navbar-brand-container">
            <Tooltip
              id="brand-tooltip"
              placement="bottomLeft"
              title={brand.tooltip}
              arrowPointAtCenter
            >
              {isFrontendRoute(window.location.pathname) ? (
                <GenericLink className="navbar-brand" to={brandPath}>
                  <img src={brand.icon} alt={brand.alt} />
                </GenericLink>
              ) : (
                <a className="navbar-brand" href={brandPath}>
                  <img src={brand.icon} alt={brand.alt} />
                </a>
              )}
            </Tooltip>
          </div>

          {!screens.md && (
            <div style={{ padding: '0 16px 16px' }}>
              <Button
                size="large"
                color="black"
                type="link"
                onClick={() => {
                  setMenuOpen(!menuOpen);
                }}
                icon={menuOpen ? <CloseOutlined /> : <MenuOutlined />}
              />
            </div>
          )}

          <DropdownMenu
            mode={showMenu}
            data-test="navbar-top"
            className="main-nav"
            style={{
              maxHeight: !screens.md && !menuOpen ? '0' : 'none',
              flex: 1,
              overflowY: 'auto',
              borderRight: 'none',
            }}
            selectedKeys={activeMenuKeys}
            openKeys={openKeys}
            onOpenChange={keys => handleOpenKeysChange(keys as string[])}
          >
            {menu.map((item, index) => {
              const props = {
                ...item,
                index: item.index ?? index,
                isFrontendRoute: isFrontendRoute(item.url),
                childs: item.childs?.map(c => {
                  if (typeof c === 'string') {
                    return c;
                  }

                  return {
                    ...c,
                    isFrontendRoute: isFrontendRoute(c.url),
                  };
                }),
              };

              return renderSubMenu(props);
            })}
            <DropdownMenu.Item role="presentation">
              <a
                role="button"
                href={bootstrapData.common.docs_url}
                rel="noreferrer noopener"
                target="_blank"
              >
                <span>
                  <ReadOutlined />
                </span>
                文档
              </a>
            </DropdownMenu.Item>
          </DropdownMenu>

          <div style={{ marginTop: 'auto' }}>
            <RightMenu
              align="flex-start"
              settings={settings}
              navbarRight={navbarRight}
              isFrontendRoute={isFrontendRoute}
              environmentTag={environmentTag}
            />
          </div>
        </div>
      </StyledHeader>
    </>
  );
}

// transform the menu data to reorganize components
export default function MenuWrapper({ data, ...rest }: MenuProps) {
  const newMenuData = {
    ...data,
  };
  // Menu items that should go into settings dropdown
  const settingsMenus = {
    Data: true,
    Security: true,
    Manage: true,
  };

  // Cycle through menu.menu to build out cleanedMenu and settings
  const cleanedMenu: MenuObjectProps[] = [];
  const settings: MenuObjectProps[] = [];
  newMenuData.menu.forEach((item: any) => {
    if (!item || item.name === 'Home') {
      return;
    }

    const children: (MenuObjectProps | string)[] = [];
    const newItem = {
      ...item,
    };

    // Filter childs
    if (item.childs) {
      item.childs.forEach((child: MenuObjectChildProps | string) => {
        if (typeof child === 'string') {
          children.push(child);
        } else if ((child as MenuObjectChildProps).label) {
          children.push(child);
        }
      });

      newItem.childs = children;
    }

    if (!settingsMenus.hasOwnProperty(item.name)) {
      cleanedMenu.push(newItem);
    } else {
      settings.push(newItem);
    }
  });

  newMenuData.menu = cleanedMenu;
  newMenuData.settings = settings;

  return <Menu data={newMenuData} {...rest} />;
}
