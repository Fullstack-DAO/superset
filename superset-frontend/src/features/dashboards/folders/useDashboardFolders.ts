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
import { useCallback, useEffect, useState } from 'react';

import {
  DashboardFolder,
  fetchDashboardFolders,
  getDashboardFoldersCache,
  subscribeDashboardFolders,
} from './api';

export default function useDashboardFolders() {
  const [dashboardFolders, setDashboardFolders] = useState<DashboardFolder[]>(
    () => getDashboardFoldersCache() || [],
  );
  const [dashboardFoldersLoading, setDashboardFoldersLoading] = useState(
    () => !getDashboardFoldersCache(),
  );

  const refreshDashboardFolders = useCallback(async (force = true) => {
    setDashboardFoldersLoading(true);
    try {
      const folders = await fetchDashboardFolders({ force });
      setDashboardFolders(folders);
      return folders;
    } finally {
      setDashboardFoldersLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!getDashboardFoldersCache()) {
      refreshDashboardFolders(false).catch(() => undefined);
    }

    return subscribeDashboardFolders(folders => {
      if (folders) {
        setDashboardFolders(folders);
        setDashboardFoldersLoading(false);
        return;
      }

      refreshDashboardFolders().catch(() => undefined);
    });
  }, [refreshDashboardFolders]);

  return {
    dashboardFolders,
    dashboardFoldersLoading,
    refreshDashboardFolders,
  };
}