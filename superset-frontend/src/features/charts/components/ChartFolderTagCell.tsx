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
import { TreeSelect } from 'antd';
import { FeatureFlag, isFeatureEnabled, styled, t } from '@superset-ui/core';

import Button from 'src/components/Button';
import { FormLabel } from 'src/components/Form';
import { Input } from 'src/components/Input';
import Modal from 'src/components/Modal';
import { TagsList } from 'src/components/Tags';
import Chart from 'src/types/Chart';
import TagType from 'src/types/TagType';
import {
  addTag,
  deleteTaggedObjects,
  OBJECT_TYPES,
} from 'src/features/tags/tags';
import {
  ChartFolder,
  syncChartFoldersForChart,
} from 'src/features/charts/folders/api';
import {
  buildFolderTreeSelectData,
  buildFolderTreeSelectValues,
  getFolderExpandedKeys,
} from 'src/features/folders/utils';

type FolderSelectValue = {
  value: string;
  label: string;
};

const FolderSelect = styled(TreeSelect as any)`
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

const FolderModalContent = styled.div`
  min-width: 280px;

  .folder-chart-name {
    margin-bottom: ${({ theme }) => theme.gridUnit * 4}px;
  }

  .folder-chart-input {
    cursor: default;
  }

  .folder-chart-select {
    width: 100%;
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

const EmptyFolderTrigger = styled.span<{ clickable: boolean }>`
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

type FolderModalFooterProps = {
  onCancel: () => void;
  onSave: () => void;
  isSaving: boolean;
  stopClickPropagation: (event: React.MouseEvent<HTMLElement>) => void;
  closeModal?: () => void;
};

const FolderModalFooter = ({
  onCancel,
  onSave,
  isSaving,
  stopClickPropagation,
}: FolderModalFooterProps) => (
  <div role="presentation" onClick={stopClickPropagation}>
    <Button buttonStyle="secondary" onClick={onCancel} cta>
      {t('Cancel')}
    </Button>
    <Button buttonStyle="primary" onClick={onSave} disabled={isSaving} cta>
      {isSaving ? t('Saving...') : t('Save')}
    </Button>
  </div>
);

interface ChartFolderTagCellProps {
  chart: Chart;
  canEdit: boolean;
  chartFolders: ChartFolder[];
  refreshChartFolders: (force?: boolean) => Promise<ChartFolder[]>;
  onOpenRequest?: (chart: Chart, canEdit: boolean) => void;
  hideTrigger?: boolean;
  openOnMount?: boolean;
  onClose?: () => void;
}

export default function ChartFolderTagCell({
  chart,
  canEdit,
  chartFolders,
  refreshChartFolders,
  onOpenRequest,
  hideTrigger = false,
  openOnMount = false,
  onClose,
}: ChartFolderTagCellProps) {
  const isTaggingEnabled = isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM);
  const isMountedRef = useRef(true);
  const didAutoOpenRef = useRef(false);
  const [chartTags, setChartTags] = useState<TagType[]>(chart.tags || []);
  const [showFolderModal, setShowFolderModal] = useState(false);
  const [selectedFolderIds, setSelectedFolderIds] = useState<string[]>([]);
  const [expandedFolderKeys, setExpandedFolderKeys] = useState<string[]>([]);
  const [isSavingFolders, setIsSavingFolders] = useState(false);

  useEffect(() => {
    isMountedRef.current = true;
    return () => {
      isMountedRef.current = false;
    };
  }, []);

  useEffect(() => {
    setChartTags(chart.tags || []);
  }, [chart.tags]);

  const currentFolders = useMemo(
    () =>
      chartFolders
        .filter(folder => folder.items.some(item => item.chartId === chart.id))
        .map(folder => ({
          id: folder.id,
          name: folder.name,
          fullPath: folder.fullPath,
        })),
    [chart.id, chartFolders],
  );

  const visibleTags = useMemo(
    () =>
      currentFolders.map(folder => {
        const folderTagName = folder.fullPath || folder.name;
        const existingTag = chartTags.find(
          tag => tag.name === folderTagName || tag.name === folder.name,
        );
        return {
          ...existingTag,
          id: existingTag?.id ?? folder.id,
          name: folderTagName,
          type: existingTag?.type ?? 1,
          toolTipTitle: folderTagName,
        } as TagType;
      }),
    [chartTags, currentFolders],
  );

  const folderOptions = useMemo(
    () => buildFolderTreeSelectData(chartFolders),
    [chartFolders],
  );

  const selectedFolderValues = useMemo<FolderSelectValue[]>(
    () => buildFolderTreeSelectValues(selectedFolderIds, chartFolders),
    [chartFolders, selectedFolderIds],
  );

  const defaultExpandedFolderKeys = useMemo(
    () => getFolderExpandedKeys(selectedFolderIds, chartFolders),
    [chartFolders, selectedFolderIds],
  );

  useEffect(() => {
    if (showFolderModal) {
      setExpandedFolderKeys(defaultExpandedFolderKeys);
    }
  }, [defaultExpandedFolderKeys, showFolderModal]);

  const isInteractive = canEdit;
  const emptyTagDisplay = canEdit ? t('选择分类') : t('无分类');

  const syncLatestFolders = useCallback(async () => {
    try {
      const latestFolders = await refreshChartFolders();
      if (!isMountedRef.current) {
        return;
      }
      setSelectedFolderIds(
        latestFolders
          .filter(folder => folder.items.some(item => item.chartId === chart.id))
          .map(folder => folder.id),
      );
    } catch {
      // Keep the modal responsive even if folder refresh fails.
    }
  }, [chart.id, refreshChartFolders]);

  const openFolderModal = useCallback(
    async (event?: React.MouseEvent<HTMLElement>) => {
      event?.preventDefault();
      event?.stopPropagation();

      if (onOpenRequest) {
        onOpenRequest(chart, canEdit);
        return;
      }

      setShowFolderModal(true);
      setSelectedFolderIds(currentFolders.map(folder => folder.id));

      await syncLatestFolders();
    },
    [canEdit, chart, currentFolders, onOpenRequest, syncLatestFolders],
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
    setShowFolderModal(true);
    setSelectedFolderIds(currentFolders.map(folder => folder.id));
    syncLatestFolders();
  }, [currentFolders, openOnMount, syncLatestFolders]);

  const closeFolderModal = useCallback(() => {
    setShowFolderModal(false);
    setSelectedFolderIds(currentFolders.map(folder => folder.id));
    onClose?.();
  }, [currentFolders, onClose]);

  const addChartFolderTag = useCallback(
    async (chartId: number, folderName: string) => {
      if (!isTaggingEnabled || !folderName.trim()) {
        return;
      }

      await new Promise<void>((resolve, reject) => {
        addTag(
          {
            objectType: OBJECT_TYPES.CHART,
            objectId: chartId,
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

  const deleteChartFolderTag = useCallback(
    async (chartId: number, folderName: string) => {
      if (!isTaggingEnabled || !folderName.trim()) {
        return;
      }

      await new Promise<void>((resolve, reject) => {
        deleteTaggedObjects(
          {
            objectType: OBJECT_TYPES.CHART,
            objectId: chartId,
          },
          { name: folderName } as TagType,
          () => resolve(),
          errorText => reject(new Error(errorText)),
        );
      });
    },
    [isTaggingEnabled],
  );

  const saveFolders = useCallback(async () => {
    const normalizedNextFolderIds = Array.from(
      new Set(selectedFolderIds.map(id => id.trim()).filter(Boolean)),
    );
    const previousFolderNames = currentFolders.map(
      folder => folder.fullPath || folder.name,
    );
    const currentMenuFolderNames = chartFolders.map(
      folder => folder.fullPath || folder.name,
    );
    const existingChartTagNames = new Set(chartTags.map(tag => tag.name));
    const nextFolderNames = chartFolders
      .filter(folder => normalizedNextFolderIds.includes(folder.id))
      .map(folder => folder.fullPath || folder.name);
    const addedFolderNames = nextFolderNames.filter(
      name => !previousFolderNames.includes(name),
    );
    const removedFolderNames = previousFolderNames.filter(
      name => !nextFolderNames.includes(name) && existingChartTagNames.has(name),
    );
    const staleFolderTagNames = chartTags
      .filter(
        tag =>
          (tag.type === 'TagTypes.custom' || tag.type === 1) &&
          previousFolderNames.includes(tag.name) &&
          !currentMenuFolderNames.includes(tag.name),
      )
      .map(tag => tag.name);
    const staleFolderTagNameSet = new Set(staleFolderTagNames);

    setIsSavingFolders(true);

    try {
      await syncChartFoldersForChart(
        chart.id,
        normalizedNextFolderIds,
        chartFolders,
      );

      await Promise.allSettled([
        ...addedFolderNames.map(folderName =>
          addChartFolderTag(chart.id, folderName),
        ),
        ...removedFolderNames.map(folderName =>
          deleteChartFolderTag(chart.id, folderName),
        ),
        ...staleFolderTagNames.map(folderName =>
          deleteChartFolderTag(chart.id, folderName),
        ),
      ]);

      const nextFolderTagNames = new Set(nextFolderNames);
      const nonFolderTags = chartTags.filter(
        tag =>
          !previousFolderNames.includes(tag.name) &&
          !staleFolderTagNameSet.has(tag.name),
      );
      const nextFolderTags = nextFolderNames.map(folderName => {
        const existingTag = chartTags.find(tag => tag.name === folderName);
        return existingTag || ({ name: folderName, type: 1 } as TagType);
      });

      setChartTags([
        ...nonFolderTags.filter(tag => !nextFolderTagNames.has(tag.name)),
        ...nextFolderTags,
      ]);
      setShowFolderModal(false);
      onClose?.();
    } finally {
      setIsSavingFolders(false);
    }
  }, [
    addChartFolderTag,
    chart.id,
    chartFolders,
    chartTags,
    currentFolders,
    deleteChartFolderTag,
    onClose,
    selectedFolderIds,
  ]);

  const stopModalClickPropagation = useCallback(
    (event: React.MouseEvent<HTMLElement>) => {
      event.preventDefault();
      event.stopPropagation();
    },
    [],
  );

  return (
    <>
      {!hideTrigger && (
        <TagCell
          clickable={isInteractive}
          role={isInteractive ? 'button' : undefined}
          tabIndex={isInteractive ? 0 : undefined}
          onClick={isInteractive ? openFolderModal : undefined}
          onKeyDown={
            isInteractive
              ? event => {
                  if (event.key === 'Enter' || event.key === ' ') {
                    openFolderModal(
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
                onClick: canEdit ? openFolderModal : undefined,
              }))}
              maxTags={3}
            />
          ) : (
            <EmptyFolderTrigger
              clickable={canEdit}
              role={canEdit ? 'button' : undefined}
              tabIndex={canEdit ? 0 : undefined}
              onClick={canEdit ? openFolderModal : undefined}
              onKeyDown={
                canEdit
                  ? event => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        openFolderModal(
                          event as unknown as React.MouseEvent<HTMLElement>,
                        );
                      }
                    }
                  : undefined
              }
            >
              {emptyTagDisplay}
            </EmptyFolderTrigger>
          )}
        </TagCell>
      )}
      <Modal
        title={<h4>{t('编辑所属分类')}</h4>}
        show={showFolderModal}
        onHide={closeFolderModal}
        wrapProps={{ onClick: stopModalClickPropagation }}
        footer={
          <FolderModalFooter
            onCancel={closeFolderModal}
            onSave={saveFolders}
            isSaving={isSavingFolders}
            stopClickPropagation={stopModalClickPropagation}
          />
        }
      >
        <FolderModalContent onClick={stopModalClickPropagation}>
          <div className="folder-chart-name">
            <FormLabel>{t('图表名称')}</FormLabel>
            <Input
              className="folder-chart-input"
              value={chart.slice_name}
              readOnly
            />
          </div>
          <FormLabel>{t('所属分类')}</FormLabel>
          <div className="folder-chart-select">
            <FolderSelect
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
              placeholder={
                folderOptions.length ? t('请选择分类') : t('暂无分类')
              }
              maxTagCount="responsive"
              dropdownStyle={{ maxHeight: 320, overflow: 'auto' }}
            />
          </div>
        </FolderModalContent>
      </Modal>
    </>
  );
}
