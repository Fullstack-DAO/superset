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
import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { TreeSelect } from 'antd';
import { FeatureFlag, isFeatureEnabled, styled, t } from '@superset-ui/core';

import Button from 'src/components/Button';
import { FormLabel } from 'src/components/Form';
import { Input } from 'src/components/Input';
import Modal from 'src/components/Modal';
import { TagsList } from 'src/components/Tags';
import Tag from 'src/types/TagType';
import { Dashboard } from 'src/views/CRUD/types';
import {
  addTag,
  deleteTaggedObjects,
  OBJECT_TYPES,
} from 'src/features/tags/tags';
import {
  DashboardFolder,
  syncDashboardFoldersForDashboard,
} from 'src/features/dashboards/folders/api';
import {
  buildFolderTreeSelectData,
  buildFolderTreeSelectValues,
  getFolderExpandedKeys,
} from 'src/features/folders/utils';

type FolderSelectValue = {
  value: string;
  label: string;
};

const FolderTagSelect = styled(TreeSelect as any)`
  ${({ theme }) => `
    width: 100%;

    .ant-select-selector {
      border-radius: ${theme.gridUnit}px;
    }

    .ant-select-selection-item {
      border-radius: ${theme.gridUnit}px;
    }
  `}
`;

const FolderTagModalContent = styled.div`
  min-width: 280px;

  .folder-tag-dashboard-name {
    margin-bottom: ${({ theme }) => theme.gridUnit * 4}px;
  }

  .folder-tag-dashboard-input {
    cursor: default;
  }
`;

const TagCell = styled.div<{ clickable: boolean }>`
  min-width: 0;
  cursor: ${({ clickable }) => (clickable ? 'pointer' : 'default')};

  .tag-list {
    min-width: 0;
    overflow: hidden;
    align-items: center;
    min-height: ${({ theme }) => theme.gridUnit * 5}px;
    flex-wrap: nowrap;

    .ant-tag {
      max-width: 100%;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      flex-shrink: 1;
      margin-top: 0;
      margin-right: 0;
      margin-bottom: 0;
      margin-left: ${({ theme }) => theme.gridUnit}px;
      border-radius: ${({ theme }) => theme.gridUnit}px;
    }

    .ant-tag:first-of-type {
      margin-left: 0;
    }
  }
`;

const EmptyFolderTagTrigger = styled.span<{ clickable: boolean }>`
  ${({ theme, clickable }) => `
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-height: ${theme.gridUnit * 5}px;
    padding: 0 ${theme.gridUnit * 2}px;
    border-radius: ${theme.gridUnit}px;
    border: 1px solid ${
      clickable ? theme.colors.primary.light2 : theme.colors.grayscale.light2
    };
    background-color: ${
      clickable ? theme.colors.primary.light5 : theme.colors.grayscale.light5
    };
    color: ${
      clickable ? theme.colors.primary.base : theme.colors.grayscale.base
    };
    cursor: ${clickable ? 'pointer' : 'default'};
    font-size: ${theme.typography.sizes.s}px;
    white-space: nowrap;
    transition: all ${theme.transitionTiming}s ease;

    &:hover {
      text-decoration: none;
      background-color: ${
        clickable ? theme.colors.primary.light4 : theme.colors.grayscale.light5
      };
      border-color: ${
        clickable ? theme.colors.primary.light1 : theme.colors.grayscale.light2
      };
    }
  `}
`;

type FolderTagModalFooterProps = {
  onCancel: () => void;
  onSave: () => void;
  isSaving: boolean;
  stopClickPropagation: (event: React.MouseEvent<HTMLElement>) => void;
  closeModal?: () => void;
};

const FolderTagModalFooter = ({
  onCancel,
  onSave,
  isSaving,
  stopClickPropagation,
}: FolderTagModalFooterProps) => (
  <div role="presentation" onClick={stopClickPropagation}>
    <Button buttonStyle="secondary" onClick={onCancel} cta>
      {t('Cancel')}
    </Button>
    <Button buttonStyle="primary" onClick={onSave} disabled={isSaving} cta>
      {isSaving ? t('Saving...') : t('Save')}
    </Button>
  </div>
);

type DashboardWithTags = Dashboard & {
  tags?: Tag[];
};

interface DashboardFolderTagCellProps {
  dashboard: DashboardWithTags;
  canEdit: boolean;
  dashboardFolders: DashboardFolder[];
  refreshDashboardFolders: (force?: boolean) => Promise<DashboardFolder[]>;
  onOpenRequest?: (dashboard: DashboardWithTags, canEdit: boolean) => void;
  hideTrigger?: boolean;
  openOnMount?: boolean;
  onClose?: () => void;
}

export default function DashboardFolderTagCell({
  dashboard,
  canEdit,
  dashboardFolders,
  refreshDashboardFolders,
  onOpenRequest,
  hideTrigger = false,
  openOnMount = false,
  onClose,
}: DashboardFolderTagCellProps) {
  const isTaggingEnabled = isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM);
  const isMountedRef = useRef(true);
  const didAutoOpenRef = useRef(false);
  const [dashboardTags, setDashboardTags] = useState<Tag[]>(
    dashboard.tags || [],
  );
  const [showFolderTagModal, setShowFolderTagModal] = useState(false);
  const [selectedFolderIds, setSelectedFolderIds] = useState<string[]>([]);
  const [expandedFolderKeys, setExpandedFolderKeys] = useState<string[]>([]);
  const [isSavingFolderTags, setIsSavingFolderTags] = useState(false);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    setDashboardTags(dashboard.tags || []);
  }, [dashboard.tags]);

  const currentFolders = useMemo(
    () =>
      dashboardFolders
        .filter(folder =>
          folder.items.some(item => item.dashboardId === dashboard.id),
        )
        .map(folder => ({
          id: folder.id,
          name: folder.name,
          fullPath: folder.fullPath,
        })),
    [dashboard.id, dashboardFolders],
  );

  const visibleTags = useMemo(
    () =>
      currentFolders.map(folder => {
        const folderTagName = folder.fullPath || folder.name;
        const existingTag = dashboardTags.find(
          tag => tag.name === folderTagName || tag.name === folder.name,
        );
        return {
          ...existingTag,
          id: existingTag?.id ?? folder.id,
          name: folderTagName,
          type: existingTag?.type ?? 1,
          toolTipTitle: folderTagName,
        } as Tag;
      }),
    [currentFolders, dashboardTags],
  );

  const folderOptions = useMemo(
    () => buildFolderTreeSelectData(dashboardFolders),
    [dashboardFolders],
  );

  const selectedFolderValues = useMemo<FolderSelectValue[]>(
    () => buildFolderTreeSelectValues(selectedFolderIds, dashboardFolders),
    [dashboardFolders, selectedFolderIds],
  );

  const defaultExpandedFolderKeys = useMemo(
    () => getFolderExpandedKeys(selectedFolderIds, dashboardFolders),
    [dashboardFolders, selectedFolderIds],
  );

  useEffect(() => {
    if (showFolderTagModal) {
      setExpandedFolderKeys(defaultExpandedFolderKeys);
    }
  }, [defaultExpandedFolderKeys, showFolderTagModal]);

  const emptyTagDisplay = canEdit ? t('选择分类') : t('无分类');
  const isInteractive = canEdit;

  const syncLatestFolders = useCallback(async () => {
    try {
      const latestFolders = await refreshDashboardFolders();
      if (!isMountedRef.current) {
        return;
      }
      setSelectedFolderIds(
        latestFolders
          .filter(folder =>
            folder.items.some(item => item.dashboardId === dashboard.id),
          )
          .map(folder => folder.id),
      );
    } catch {
      // Keep the modal responsive even if folder refresh fails.
    }
  }, [dashboard.id, refreshDashboardFolders]);

  const openFolderTagModal = useCallback(
    async (event?: React.MouseEvent<HTMLElement>) => {
      event?.preventDefault();
      event?.stopPropagation();

      if (onOpenRequest) {
        onOpenRequest(dashboard, canEdit);
        return;
      }

      setShowFolderTagModal(true);
      setSelectedFolderIds(currentFolders.map(folder => folder.id));
      await syncLatestFolders();
    },
    [canEdit, currentFolders, dashboard, onOpenRequest, syncLatestFolders],
  );

  useEffect(() => {
    if (!openOnMount) {
      didAutoOpenRef.current = false;
      return;
    }

    if (didAutoOpenRef.current) {
      return;
    }

    didAutoOpenRef.current = true;
    setShowFolderTagModal(true);
    setSelectedFolderIds(currentFolders.map(folder => folder.id));
    syncLatestFolders();
  }, [currentFolders, openOnMount, syncLatestFolders]);

  const closeFolderTagModal = useCallback(() => {
    setShowFolderTagModal(false);
    setSelectedFolderIds(currentFolders.map(folder => folder.id));
    onClose?.();
  }, [currentFolders, onClose]);

  const stopModalClickPropagation = useCallback(
    (event: React.MouseEvent<HTMLElement>) => {
      event.preventDefault();
      event.stopPropagation();
    },
    [],
  );

  const addDashboardFolderTag = useCallback(
    async (dashboardId: number, folderName: string) => {
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
    },
    [isTaggingEnabled],
  );

  const deleteDashboardFolderTag = useCallback(
    async (dashboardId: number, folderName: string) => {
      if (!isTaggingEnabled || !folderName.trim()) {
        return;
      }

      await new Promise<void>((resolve, reject) => {
        deleteTaggedObjects(
          {
            objectType: OBJECT_TYPES.DASHBOARD,
            objectId: dashboardId,
          },
          { name: folderName } as Tag,
          () => resolve(),
          errorText => reject(new Error(errorText)),
        );
      });
    },
    [isTaggingEnabled],
  );

  const saveFolderTags = useCallback(async () => {
    const normalizedNextFolderIds = Array.from(
      new Set(selectedFolderIds.map(id => id.trim()).filter(Boolean)),
    );
    const previousFolderNames = currentFolders.map(
      folder => folder.fullPath || folder.name,
    );
    const currentMenuFolderNames = dashboardFolders.map(
      folder => folder.fullPath || folder.name,
    );
    const existingDashboardTagNames = new Set(
      dashboardTags.map(tag => tag.name),
    );
    const nextFolderNames = dashboardFolders
      .filter(folder => normalizedNextFolderIds.includes(folder.id))
      .map(folder => folder.fullPath || folder.name);
    const addedFolderNames = nextFolderNames.filter(
      name => !previousFolderNames.includes(name),
    );
    const removedFolderNames = previousFolderNames.filter(
      name =>
        !nextFolderNames.includes(name) && existingDashboardTagNames.has(name),
    );
    const staleFolderTagNames = dashboardTags
      .filter(
        tag =>
          (tag.type === 'TagTypes.custom' || tag.type === 1) &&
          previousFolderNames.includes(tag.name) &&
          !currentMenuFolderNames.includes(tag.name),
      )
      .map(tag => tag.name);
    const staleFolderTagNameSet = new Set(staleFolderTagNames);

    setIsSavingFolderTags(true);

    try {
      await syncDashboardFoldersForDashboard(
        dashboard.id,
        normalizedNextFolderIds,
        dashboardFolders,
      );

      await Promise.allSettled([
        ...addedFolderNames.map(folderName =>
          addDashboardFolderTag(dashboard.id, folderName),
        ),
        ...removedFolderNames.map(folderName =>
          deleteDashboardFolderTag(dashboard.id, folderName),
        ),
        ...staleFolderTagNames.map(folderName =>
          deleteDashboardFolderTag(dashboard.id, folderName),
        ),
      ]);

      const nextFolderTagNames = new Set(nextFolderNames);
      const nonFolderTags = dashboardTags.filter(
        tag =>
          !previousFolderNames.includes(tag.name) &&
          !staleFolderTagNameSet.has(tag.name),
      );
      const nextFolderTags = nextFolderNames.map(folderName => {
        const existingTag = dashboardTags.find(tag => tag.name === folderName);
        return existingTag || ({ name: folderName, type: 1 } as Tag);
      });

      setDashboardTags([
        ...nonFolderTags.filter(tag => !nextFolderTagNames.has(tag.name)),
        ...nextFolderTags,
      ]);
      setShowFolderTagModal(false);
      onClose?.();
    } catch {
      // Keep behavior aligned with card interactions.
    } finally {
      setIsSavingFolderTags(false);
    }
  }, [
    addDashboardFolderTag,
    currentFolders,
    dashboard.id,
    dashboardTags,
    dashboardFolders,
    deleteDashboardFolderTag,
    onClose,
    selectedFolderIds,
  ]);

  return (
    <>
      {!hideTrigger && (
        <TagCell
          clickable={isInteractive}
          role={isInteractive ? 'button' : undefined}
          tabIndex={isInteractive ? 0 : undefined}
          onClick={isInteractive ? openFolderTagModal : undefined}
          onKeyDown={
            isInteractive
              ? event => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    openFolderTagModal(
                      event as unknown as React.MouseEvent<HTMLElement>,
                    );
                  }
                }
              : undefined
          }
        >
          {visibleTags.length ? (
            <TagsList
              tags={visibleTags.map(tag => ({
                ...tag,
                onClick: canEdit ? openFolderTagModal : undefined,
              }))}
              maxTags={3}
            />
          ) : (
            <EmptyFolderTagTrigger
              clickable={canEdit}
              role={canEdit ? 'button' : undefined}
              tabIndex={canEdit ? 0 : undefined}
              onClick={canEdit ? openFolderTagModal : undefined}
              onKeyDown={
                canEdit
                  ? event => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        openFolderTagModal(
                          event as unknown as React.MouseEvent<HTMLElement>,
                        );
                      }
                    }
                  : undefined
              }
            >
              {emptyTagDisplay}
            </EmptyFolderTagTrigger>
          )}
        </TagCell>
      )}
      <Modal
        title={t('编辑所属分类')}
        show={showFolderTagModal}
        onHide={closeFolderTagModal}
        wrapProps={{ onClick: stopModalClickPropagation }}
        footer={
          <FolderTagModalFooter
            onCancel={closeFolderTagModal}
            onSave={saveFolderTags}
            isSaving={isSavingFolderTags}
            stopClickPropagation={stopModalClickPropagation}
          />
        }
      >
        <FolderTagModalContent onClick={stopModalClickPropagation}>
          <div className="folder-tag-dashboard-name">
            <FormLabel>{t('仪表盘名称')}</FormLabel>
            <Input
              className="folder-tag-dashboard-input"
              value={dashboard.dashboard_title}
              readOnly
            />
          </div>
          <FormLabel>{t('所属分类')}</FormLabel>
          <FolderTagSelect
            treeData={folderOptions}
            value={selectedFolderValues}
            treeCheckable
            treeCheckStrictly
            treeExpandedKeys={expandedFolderKeys}
            labelInValue
            showCheckedStrategy={TreeSelect.SHOW_CHILD}
            treeNodeLabelProp="fullPathLabel"
            onTreeExpand={(keys: React.Key[]) =>
              setExpandedFolderKeys(keys.map(key => String(key)))
            }
            onDropdownVisibleChange={(open: boolean) => {
              if (open) {
                setExpandedFolderKeys(defaultExpandedFolderKeys);
              }
            }}
            onChange={(value: FolderSelectValue[] | FolderSelectValue) =>
              setSelectedFolderIds(
                Array.from(
                  new Set(
                    (Array.isArray(value) ? value : [value]).map(
                      item => item.value,
                    ),
                  ),
                ),
              )
            }
            placeholder={t('请选择所属分类')}
            maxTagCount="responsive"
            dropdownStyle={{ maxHeight: 320, overflow: 'auto' }}
          />
        </FolderTagModalContent>
      </Modal>
    </>
  );
}
