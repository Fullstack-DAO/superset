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
import { SupersetClient } from '@superset-ui/core';

export const DASHBOARD_FOLDER_QUERY_KEY = 'folder';
export const DASHBOARD_FOLDERS_UPDATED_EVENT = 'dashboard-folders-updated';

export type DashboardFolderItem = {
  id: string;
  dashboardId: number;
  name: string;
  url: string;
};

export type DashboardFolder = {
  id: string;
  name: string;
  items: DashboardFolderItem[];
};

type DashboardFoldersUpdatedDetail = {
  folders?: DashboardFolder[];
};

type DashboardFolderApiItem = {
  id: number;
  dashboard_id: number;
  dashboard_title: string;
  url: string;
};

type DashboardFolderApi = {
  id: number;
  name: string;
  items: DashboardFolderApiItem[];
};

type FetchDashboardFoldersOptions = {
  force?: boolean;
  broadcast?: boolean;
};

type MutateDashboardFolderOptions = {
  skipRefresh?: boolean;
};

const DASHBOARD_FOLDERS_API_ENDPOINT = '/api/v1/dashboard_menu/';

let dashboardFoldersCache: DashboardFolder[] | null = null;
let dashboardFoldersRequest: Promise<DashboardFolder[]> | null = null;

const normalizeDashboardFolder = (folder: DashboardFolderApi): DashboardFolder => ({
  id: String(folder.id),
  name: folder.name,
  items: (folder.items || []).map(item => ({
    id: String(item.id),
    dashboardId: item.dashboard_id,
    name: item.dashboard_title,
    url: item.url,
  })),
});

const parseFolderId = (folderId: string) => Number.parseInt(folderId, 10);

const parseItemId = (itemId: string) => Number.parseInt(itemId, 10);

export const getDashboardFoldersCache = () => dashboardFoldersCache;

const setDashboardFoldersCache = (folders: DashboardFolder[]) => {
  dashboardFoldersCache = folders;
  return folders;
};

export const fetchDashboardFolders = async ({
  force = false,
  broadcast = false,
}: FetchDashboardFoldersOptions = {}): Promise<DashboardFolder[]> => {
  if (!force && dashboardFoldersCache) {
    return dashboardFoldersCache;
  }

  if (!force && dashboardFoldersRequest) {
    return dashboardFoldersRequest;
  }

  dashboardFoldersRequest = SupersetClient.get({
    endpoint: DASHBOARD_FOLDERS_API_ENDPOINT,
  })
    .then(({ json }) =>
      setDashboardFoldersCache(
        ((json?.result || []) as DashboardFolderApi[]).map(normalizeDashboardFolder),
      ),
    )
    .then(folders => {
      if (broadcast) {
        emitDashboardFoldersUpdated(folders);
      }
      return folders;
    })
    .finally(() => {
      dashboardFoldersRequest = null;
    });

  return dashboardFoldersRequest;
};

export const emitDashboardFoldersUpdated = (folders?: DashboardFolder[]) => {
  if (typeof window === 'undefined') {
    return;
  }

  window.dispatchEvent(
    new CustomEvent<DashboardFoldersUpdatedDetail>(DASHBOARD_FOLDERS_UPDATED_EVENT, {
      detail: { folders },
    }),
  );
};

export const subscribeDashboardFolders = (
  callback: (folders?: DashboardFolder[]) => void,
) => {
  if (typeof window === 'undefined') {
    return () => undefined;
  }

  const handler = (event: Event) => {
    callback((event as CustomEvent<DashboardFoldersUpdatedDetail>).detail?.folders);
  };

  window.addEventListener(DASHBOARD_FOLDERS_UPDATED_EVENT, handler);
  return () => window.removeEventListener(DASHBOARD_FOLDERS_UPDATED_EVENT, handler);
};

export const refreshAndBroadcastDashboardFolders = async () =>
  fetchDashboardFolders({ force: true, broadcast: true });

export const createDashboardFolder = async (
  name: string,
  options: MutateDashboardFolderOptions = {},
) => {
  await SupersetClient.post({
    endpoint: `${DASHBOARD_FOLDERS_API_ENDPOINT}folder`,
    jsonPayload: { name },
  });
  if (options.skipRefresh) {
    return getDashboardFoldersCache() || [];
  }
  return refreshAndBroadcastDashboardFolders();
};

export const renameDashboardFolder = async (
  folderId: string,
  name: string,
  options: MutateDashboardFolderOptions = {},
) => {
  await SupersetClient.put({
    endpoint: `${DASHBOARD_FOLDERS_API_ENDPOINT}folder/${parseFolderId(folderId)}`,
    jsonPayload: { name },
  });
  if (options.skipRefresh) {
    return getDashboardFoldersCache() || [];
  }
  return refreshAndBroadcastDashboardFolders();
};

export const deleteDashboardFolder = async (
  folderId: string,
  options: MutateDashboardFolderOptions = {},
) => {
  await SupersetClient.delete({
    endpoint: `${DASHBOARD_FOLDERS_API_ENDPOINT}folder/${parseFolderId(folderId)}`,
  });
  if (options.skipRefresh) {
    return getDashboardFoldersCache() || [];
  }
  return refreshAndBroadcastDashboardFolders();
};

export const addDashboardToFolder = async (
  folderId: string,
  dashboardId: number,
  options: MutateDashboardFolderOptions = {},
) => {
  await SupersetClient.post({
    endpoint: `${DASHBOARD_FOLDERS_API_ENDPOINT}folder/${parseFolderId(folderId)}/items`,
    jsonPayload: { dashboard_id: dashboardId },
  });
  if (options.skipRefresh) {
    return getDashboardFoldersCache() || [];
  }
  return refreshAndBroadcastDashboardFolders();
};

export const removeDashboardFromFolder = async (
  folderId: string,
  itemId: string,
  options: MutateDashboardFolderOptions = {},
) => {
  await SupersetClient.delete({
    endpoint: `${DASHBOARD_FOLDERS_API_ENDPOINT}folder/${parseFolderId(folderId)}/items/${parseItemId(itemId)}`,
  });
  if (options.skipRefresh) {
    return getDashboardFoldersCache() || [];
  }
  return refreshAndBroadcastDashboardFolders();
};

export const syncDashboardFoldersForDashboard = async (
  dashboardId: number,
  nextFolderIds: string[],
  currentFolders: DashboardFolder[],
) => {
  const normalizedNextFolderIds = Array.from(new Set(nextFolderIds));
  const currentFolderIds = currentFolders
    .filter(folder => folder.items.some(item => item.dashboardId === dashboardId))
    .map(folder => folder.id);
  const foldersToAdd = normalizedNextFolderIds.filter(
    folderId => !currentFolderIds.includes(folderId),
  );
  const itemsToRemove = currentFolders
    .filter(
      folder =>
        !normalizedNextFolderIds.includes(folder.id) &&
        folder.items.some(item => item.dashboardId === dashboardId),
    )
    .map(folder => ({
      folderId: folder.id,
      itemId: folder.items.find(item => item.dashboardId === dashboardId)?.id,
    }))
    .filter(
      (item): item is { folderId: string; itemId: string } => Boolean(item.itemId),
    );

  if (!foldersToAdd.length && !itemsToRemove.length) {
    return currentFolders;
  }

  await Promise.all([
    ...foldersToAdd.map(folderId =>
      addDashboardToFolder(folderId, dashboardId, { skipRefresh: true }),
    ),
    ...itemsToRemove.map(({ folderId, itemId }) =>
      removeDashboardFromFolder(folderId, itemId, { skipRefresh: true }),
    ),
  ]);

  return refreshAndBroadcastDashboardFolders();
};