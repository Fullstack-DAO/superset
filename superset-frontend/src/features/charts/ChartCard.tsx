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
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import {
  isFeatureEnabled,
  FeatureFlag,
  styled,
  t,
  useTheme,
} from '@superset-ui/core';
import { Link, useHistory } from 'react-router-dom';
import ConfirmStatusChange from 'src/components/ConfirmStatusChange';
import Icons from 'src/components/Icons';
import Chart from 'src/types/Chart';

import ListViewCard from 'src/components/ListViewCard';
import Label from 'src/components/Label';
import { AntdDropdown, Select } from 'src/components';
import { Menu } from 'src/components/Menu';
import FaveStar from 'src/components/FaveStar';
import FacePile from 'src/components/FacePile';
import Modal from 'src/components/Modal';
import Button from 'src/components/Button';
import { FormLabel } from 'src/components/Form';
import { Input } from 'src/components/Input';
import { TagsList } from 'src/components/Tags';
import TagType from 'src/types/TagType';
import {
  addTag,
  deleteTaggedObjects,
  OBJECT_TYPES,
} from 'src/features/tags/tags';
import { handleChartDelete, CardStyles } from 'src/views/CRUD/utils';
import {
  syncChartFoldersForChart,
} from 'src/features/charts/folders/api';
import useChartFolders from 'src/features/charts/folders/useChartFolders';

const StyledCardStyles = styled(CardStyles)`
  [data-test='styled-card'] {
    border-radius: 12px;
    box-shadow: 0px 4px 12px 0px rgba(57, 47, 113, 0.1);
  }

  [data-test='styled-card']:hover {
    box-shadow: 0px 4px 12px 0px rgba(57, 47, 113, 0.1);
  }
`;

const FolderSelect = styled(Select)`
  ${({ theme }) => `
    && .ant-select-selector {
      border-radius: ${theme.gridUnit}px;
    }

    .ant-select-selection-item {
      border-radius: ${theme.gridUnit}px;
    }
  `}
`;

const FolderModalContent = styled.div`
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

const CardMetaRow = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: ${({ theme }) => theme.gridUnit * 2}px;
  min-height: ${({ theme }) => theme.gridUnit * 7}px;
  width: 100%;

  .card-meta-left {
    min-width: 0;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .card-meta-right {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    flex-shrink: 0;
    margin-left: auto;
    min-height: ${({ theme }) => theme.gridUnit * 5}px;
  }

  .tag-list {
    align-items: center;
    justify-content: flex-end;
    min-height: ${({ theme }) => theme.gridUnit * 5}px;

    .ant-tag {
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
    color: ${clickable ? theme.colors.primary.base : theme.colors.grayscale.base};
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

type ChartPermissions = {
  can_delete: boolean;
  can_export: boolean;
  can_write: boolean;
};

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

interface ChartCardProps {
  chart: Chart;
  hasPerm: (perm: string) => boolean;
  permissions?: ChartPermissions;
  openChartEditModal: (chart: Chart) => void;
  bulkSelectEnabled: boolean;
  addDangerToast: (msg: string) => void;
  addSuccessToast: (msg: string) => void;
  refreshData: () => void;
  loading?: boolean;
  saveFavoriteStatus: (id: number, isStarred: boolean) => void;
  favoriteStatus: boolean;
  chartFilter?: string;
  userId?: string | number;
  showThumbnails?: boolean;
  handleBulkChartExport: (chartsToExport: Chart[]) => void;
}

export default function ChartCard({
  chart,
  hasPerm,
  permissions,
  openChartEditModal,
  bulkSelectEnabled,
  addDangerToast,
  addSuccessToast,
  refreshData,
  loading,
  showThumbnails,
  saveFavoriteStatus,
  favoriteStatus,
  chartFilter,
  userId,
  handleBulkChartExport,
}: ChartCardProps) {
  const history = useHistory();
  const isTaggingEnabled = isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM);
  const canEdit = permissions?.can_write ?? hasPerm('can_write');
  const canDelete = permissions?.can_delete ?? hasPerm('can_write');
  const canExport =
    permissions?.can_export ??
    (hasPerm('can_export') && isFeatureEnabled(FeatureFlag.VERSIONED_EXPORT));
  const theme = useTheme();
  const { chartFolders, refreshChartFolders } = useChartFolders();
  const [chartTags, setChartTags] = useState<TagType[]>(chart.tags || []);
  const [showFolderModal, setShowFolderModal] = useState(false);
  const [selectedFolderIds, setSelectedFolderIds] = useState<string[]>([]);
  const [isSavingFolders, setIsSavingFolders] = useState(false);
  const canManageFolders = canEdit;

  useEffect(() => {
    setChartTags(chart.tags || []);
  }, [chart.tags]);

  const currentFolders = useMemo(
    () =>
      chartFolders
        .filter(folder => folder.items.some(item => item.chartId === chart.id))
        .map(folder => ({ id: folder.id, name: folder.name })),
    [chart.id, chartFolders],
  );

  const folderOptions = useMemo(
    () =>
      chartFolders.map(folder => ({
        label: folder.name,
        value: folder.id,
      })),
    [chartFolders],
  );

  const openFolderModal = useCallback(async (event?: React.MouseEvent<HTMLElement>) => {
    event?.preventDefault();
    event?.stopPropagation();
    const latestFolders = await refreshChartFolders();
    setSelectedFolderIds(
      latestFolders
        .filter(folder => folder.items.some(item => item.chartId === chart.id))
        .map(folder => folder.id),
    );
    setShowFolderModal(true);
  }, [chart.id, refreshChartFolders]);

  const closeFolderModal = useCallback(() => {
    setShowFolderModal(false);
    setSelectedFolderIds(currentFolders.map(folder => folder.id));
  }, [currentFolders]);

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
    const previousFolderNames = currentFolders.map(folder => folder.name);
    const nextFolderNames = chartFolders
      .filter(folder => normalizedNextFolderIds.includes(folder.id))
      .map(folder => folder.name);
    const addedFolderNames = nextFolderNames.filter(
      name => !previousFolderNames.includes(name),
    );
    const removedFolderNames = previousFolderNames.filter(
      name => !nextFolderNames.includes(name),
    );

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
      ]);

      const nextFolderTagNames = new Set(nextFolderNames);
      const nonFolderTags = chartTags.filter(
        tag => !previousFolderNames.includes(tag.name),
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
    selectedFolderIds,
  ]);

  const stopModalClickPropagation = useCallback(
    (event: React.MouseEvent<HTMLElement>) => {
      event.preventDefault();
      event.stopPropagation();
    },
    [],
  );

  const menu = (
    <Menu>
      {canDelete && (
        <Menu.Item>
          <ConfirmStatusChange
            title={t('Please confirm')}
            description={
              <>
                {t('Are you sure you want to delete')} <b>{chart.slice_name}</b>
                ?
              </>
            }
            onConfirm={() =>
              handleChartDelete(
                chart,
                addSuccessToast,
                addDangerToast,
                refreshData,
                chartFilter,
                userId,
              )
            }
          >
            {confirmDelete => (
              <div
                data-test="chart-list-delete-option"
                role="button"
                tabIndex={0}
                className="action-button"
                onClick={confirmDelete}
              >
                <Icons.Trash iconSize="l" /> {t('Delete')}
              </div>
            )}
          </ConfirmStatusChange>
        </Menu.Item>
      )}
      {canExport && (
        <Menu.Item>
          <div
            role="button"
            tabIndex={0}
            onClick={() => handleBulkChartExport([chart])}
          >
            <Icons.Share iconSize="l" /> {t('Export')}
          </div>
        </Menu.Item>
      )}
      {canEdit && (
        <Menu.Item>
          <div
            data-test="chart-list-edit-option"
            role="button"
            tabIndex={0}
            onClick={() => openChartEditModal(chart)}
          >
            <Icons.EditAlt iconSize="l" /> {t('Edit')}
          </div>
        </Menu.Item>
      )}
    </Menu>
  );
  return (
    <StyledCardStyles
      onClick={() => {
        if (!bulkSelectEnabled && !showFolderModal && chart.url) {
          history.push(chart.url);
        }
      }}
    >
      <ListViewCard
        loading={loading}
        title={chart.slice_name}
        certifiedBy={chart.certified_by}
        certificationDetails={chart.certification_details}
        // cover={
        //   !isFeatureEnabled(FeatureFlag.THUMBNAILS) || !showThumbnails ? (
        //     <></>
        //   ) : null
        // }
        url={bulkSelectEnabled ? undefined : chart.url}
        // imgURL={chart.thumbnail_url || ''}
        imgFallbackURL="/static/assets/images/chart-list-icon.svg"
        description={
          <CardMetaRow>
            <span className="card-meta-left">
              {`${chart.changed_on_delta_humanized}`}
            </span>
            <span className="card-meta-right">
              {currentFolders.length ? (
                <TagsList
                  tags={currentFolders.map(folder => ({
                    id: folder.id,
                    name: folder.name,
                    onClick: openFolderModal,
                    toolTipTitle: folder.name,
                  }))}
                  maxTags={3}
                />
              ) : (
                <EmptyFolderTrigger
                  clickable={canManageFolders}
                  role={canManageFolders ? 'button' : undefined}
                  tabIndex={canManageFolders ? 0 : undefined}
                  onClick={canManageFolders ? openFolderModal : undefined}
                  onKeyDown={
                    canManageFolders
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
                  {canEdit ? t('选择分类') : t('无分类')}
                </EmptyFolderTrigger>
              )}
            </span>
          </CardMetaRow>
        }
        coverLeft={<FacePile users={chart.owners || []} />}
        coverRight={<Label type="secondary">{chart.datasource_name_text}</Label>}
        linkComponent={Link}
        actions={
          <ListViewCard.Actions
            onClick={e => {
              e.stopPropagation();
              e.preventDefault();
            }}
          >
            {userId && (
              <FaveStar
                itemId={chart.id}
                saveFaveStar={saveFavoriteStatus}
                isStarred={favoriteStatus}
              />
            )}
            <AntdDropdown overlay={menu}>
              <Icons.MoreHoriz iconColor={theme.colors.grayscale.base} iconSize="m" />
            </AntdDropdown>
          </ListViewCard.Actions>
        }
      />
      <Modal
        show={showFolderModal}
        onHide={closeFolderModal}
        title={<h4>{t('编辑所属分类')}</h4>}
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
              ariaLabel="chart-folder-select"
              mode="multiple"
              options={folderOptions}
              value={selectedFolderIds}
              onChange={(values: string[]) => setSelectedFolderIds(values)}
              placeholder={
                folderOptions.length ? t('请选择分类') : t('暂无分类')
              }
            />
          </div>
        </FolderModalContent>
      </Modal>
    </StyledCardStyles>
  );
}
