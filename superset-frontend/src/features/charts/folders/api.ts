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

export const CHART_FOLDER_QUERY_KEY = 'folder';
export const CHART_FOLDERS_UPDATED_EVENT = 'chart-folders-updated';

export type ChartFolderItem = {
  id: string;
  chartId: number;
  name: string;
  url: string;
};

export type ChartFolder = {
  id: string;
  name: string;
  parentId: string | null;
  fullPath: string;
  items: ChartFolderItem[];
};

type ChartFoldersUpdatedDetail = {
  folders?: ChartFolder[];
};

type ChartFolderApiItem = {
  id: number;
  chart_id: number;
  slice_name: string;
  url: string;
};

type ChartFolderApi = {
  id: number;
  name: string;
  parent_id: number | null;
  full_path: string;
  items: ChartFolderApiItem[];
};

type ChartFolderPayload = {
  name: string;
  parentId?: string | null;
};

type FetchChartFoldersOptions = {
  force?: boolean;
  broadcast?: boolean;
};

type MutateChartFolderOptions = {
  skipRefresh?: boolean;
};

const CHART_FOLDERS_API_ENDPOINT = '/api/v1/chart_menu/';

let chartFoldersCache: ChartFolder[] | null = null;
let chartFoldersRequest: Promise<ChartFolder[]> | null = null;

const normalizeChartFolder = (folder: ChartFolderApi): ChartFolder => ({
  id: String(folder.id),
  name: folder.name,
  parentId: folder.parent_id == null ? null : String(folder.parent_id),
  fullPath: folder.full_path,
  items: (folder.items || []).map(item => ({
    id: String(item.id),
    chartId: item.chart_id,
    name: item.slice_name,
    url: item.url,
  })),
});

const parseFolderId = (folderId: string) => Number.parseInt(folderId, 10);

const parseItemId = (itemId: string) => Number.parseInt(itemId, 10);

export const getChartFoldersCache = () => chartFoldersCache;

const setChartFoldersCache = (folders: ChartFolder[]) => {
  chartFoldersCache = folders;
  return folders;
};

export const fetchChartFolders = async ({
  force = false,
  broadcast = false,
}: FetchChartFoldersOptions = {}): Promise<ChartFolder[]> => {
  if (!force && chartFoldersCache) {
    return chartFoldersCache;
  }

  if (!force && chartFoldersRequest) {
    return chartFoldersRequest;
  }

  chartFoldersRequest = SupersetClient.get({
    endpoint: CHART_FOLDERS_API_ENDPOINT,
  })
    .then(({ json }) =>
      setChartFoldersCache(
        ((json?.result || []) as ChartFolderApi[]).map(normalizeChartFolder),
      ),
    )
    .then(folders => {
      if (broadcast) {
        emitChartFoldersUpdated(folders);
      }
      return folders;
    })
    .finally(() => {
      chartFoldersRequest = null;
    });

  return chartFoldersRequest;
};

export const emitChartFoldersUpdated = (folders?: ChartFolder[]) => {
  if (typeof window === 'undefined') {
    return;
  }

  window.dispatchEvent(
    new CustomEvent<ChartFoldersUpdatedDetail>(CHART_FOLDERS_UPDATED_EVENT, {
      detail: { folders },
    }),
  );
};

export const subscribeChartFolders = (
  callback: (folders?: ChartFolder[]) => void,
) => {
  if (typeof window === 'undefined') {
    return () => undefined;
  }

  const handler = (event: Event) => {
    callback((event as CustomEvent<ChartFoldersUpdatedDetail>).detail?.folders);
  };

  window.addEventListener(CHART_FOLDERS_UPDATED_EVENT, handler);
  return () => window.removeEventListener(CHART_FOLDERS_UPDATED_EVENT, handler);
};

export const refreshAndBroadcastChartFolders = async () =>
  fetchChartFolders({ force: true, broadcast: true });

export const createChartFolder = async (
  { name, parentId = null }: ChartFolderPayload,
  options: MutateChartFolderOptions = {},
) => {
  await SupersetClient.post({
    endpoint: `${CHART_FOLDERS_API_ENDPOINT}folder`,
    jsonPayload: {
      name,
      parent_id: parentId ? parseFolderId(parentId) : null,
    },
  });
  if (options.skipRefresh) {
    return getChartFoldersCache() || [];
  }
  return refreshAndBroadcastChartFolders();
};

export const renameChartFolder = async (
  folderId: string,
  { name, parentId = null }: ChartFolderPayload,
  options: MutateChartFolderOptions = {},
) => {
  await SupersetClient.put({
    endpoint: `${CHART_FOLDERS_API_ENDPOINT}folder/${parseFolderId(folderId)}`,
    jsonPayload: {
      name,
      parent_id: parentId ? parseFolderId(parentId) : null,
    },
  });
  if (options.skipRefresh) {
    return getChartFoldersCache() || [];
  }
  return refreshAndBroadcastChartFolders();
};

export const deleteChartFolder = async (
  folderId: string,
  options: MutateChartFolderOptions = {},
) => {
  await SupersetClient.delete({
    endpoint: `${CHART_FOLDERS_API_ENDPOINT}folder/${parseFolderId(folderId)}`,
  });
  if (options.skipRefresh) {
    return getChartFoldersCache() || [];
  }
  return refreshAndBroadcastChartFolders();
};

export const addChartToFolder = async (
  folderId: string,
  chartId: number,
  options: MutateChartFolderOptions = {},
) => {
  await SupersetClient.post({
    endpoint: `${CHART_FOLDERS_API_ENDPOINT}folder/${parseFolderId(folderId)}/items`,
    jsonPayload: { chart_id: chartId },
  });
  if (options.skipRefresh) {
    return getChartFoldersCache() || [];
  }
  return refreshAndBroadcastChartFolders();
};

export const removeChartFromFolder = async (
  folderId: string,
  itemId: string,
  options: MutateChartFolderOptions = {},
) => {
  await SupersetClient.delete({
    endpoint: `${CHART_FOLDERS_API_ENDPOINT}folder/${parseFolderId(folderId)}/items/${parseItemId(itemId)}`,
  });
  if (options.skipRefresh) {
    return getChartFoldersCache() || [];
  }
  return refreshAndBroadcastChartFolders();
};

export const syncChartFoldersForChart = async (
  chartId: number,
  nextFolderIds: string[],
  currentFolders: ChartFolder[],
) => {
  const normalizedNextFolderIds = Array.from(new Set(nextFolderIds));
  const currentFolderIds = currentFolders
    .filter(folder => folder.items.some(item => item.chartId === chartId))
    .map(folder => folder.id);
  const foldersToAdd = normalizedNextFolderIds.filter(
    folderId => !currentFolderIds.includes(folderId),
  );
  const itemsToRemove = currentFolders
    .filter(
      folder =>
        !normalizedNextFolderIds.includes(folder.id) &&
        folder.items.some(item => item.chartId === chartId),
    )
    .map(folder => ({
      folderId: folder.id,
      itemId: folder.items.find(item => item.chartId === chartId)?.id,
    }))
    .filter(
      (item): item is { folderId: string; itemId: string } => Boolean(item.itemId),
    );

  if (!foldersToAdd.length && !itemsToRemove.length) {
    return currentFolders;
  }

  await Promise.all([
    ...foldersToAdd.map(folderId =>
      addChartToFolder(folderId, chartId, { skipRefresh: true }),
    ),
    ...itemsToRemove.map(({ folderId, itemId }) =>
      removeChartFromFolder(folderId, itemId, { skipRefresh: true }),
    ),
  ]);

  return refreshAndBroadcastChartFolders();
};
