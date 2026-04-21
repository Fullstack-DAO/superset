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
import { Link, useHistory } from 'react-router-dom';
import {
  FeatureFlag,
  isFeatureEnabled,
  styled,
  t,
  useTheme,
} from '@superset-ui/core';
import { CardStyles } from 'src/views/CRUD/utils';
import { AntdDropdown, Select } from 'src/components';
import { Menu } from 'src/components/Menu';
import ListViewCard from 'src/components/ListViewCard';
import Icons from 'src/components/Icons';
import FacePile from 'src/components/FacePile';
import FaveStar from 'src/components/FaveStar';
import { Input } from 'src/components/Input';
import { TagsList } from 'src/components/Tags';
import { FormLabel } from 'src/components/Form';
import Modal from 'src/components/Modal';
import Button from 'src/components/Button';
import Tag from 'src/types/TagType';
import {
  addTag,
  deleteTaggedObjects,
  OBJECT_TYPES,
} from 'src/features/tags/tags';
import { Dashboard } from 'src/views/CRUD/types';
import {
  syncDashboardFoldersForDashboard,
} from 'src/features/dashboards/folders/api';
import useDashboardFolders from 'src/features/dashboards/folders/useDashboardFolders';

const StyledCardStyles = styled(CardStyles)`
  [data-test='styled-card'] {
    border-radius: 12px;
    box-shadow: 0px 4px 12px 0px rgba(57, 47, 113, 0.1);
  }

  [data-test='styled-card']:hover {
    box-shadow: 0px 4px 12px 0px rgba(57, 47, 113, 0.1);
  }
`;

const FolderTagSelect = styled(Select)`
  ${({ theme }) => `
    && .ant-select-selector {
      border-radius: ${theme.gridUnit}px;
    }

    .ant-select-selection-item {
      border-radius: ${theme.gridUnit}px;
    }
  `}
`;

const FolderTagModalContent = styled.div`
  .folder-tag-dashboard-name {
    margin-bottom: ${({ theme }) => theme.gridUnit * 4}px;
  }

  .folder-tag-dashboard-input {
    cursor: default;
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

type DashboardPermissions = {
  can_delete: boolean;
  can_export: boolean;
  can_write: boolean;
};

interface DashboardCardProps {
  isChart?: boolean;
  dashboard: Dashboard;
  hasPerm: (name: string) => boolean;
  permissions?: DashboardPermissions;
  bulkSelectEnabled: boolean;
  loading: boolean;
  openDashboardEditModal?: (d: Dashboard) => void;
  saveFavoriteStatus: (id: number, isStarred: boolean) => void;
  favoriteStatus: boolean;
  userId?: string | number;
  showThumbnails?: boolean;
  handleBulkDashboardExport: (dashboardsToExport: Dashboard[]) => void;
  onDelete: (dashboard: Dashboard) => void;
}

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

function DashboardCard({
  dashboard,
  hasPerm,
  permissions,
  bulkSelectEnabled,
  userId,
  openDashboardEditModal,
  favoriteStatus,
  saveFavoriteStatus,
  showThumbnails,
  handleBulkDashboardExport,
  onDelete,
}: DashboardCardProps) {
  const dashboardWithTags = dashboard as DashboardWithTags;
  const history = useHistory();
  const isTaggingEnabled = isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM);
  const canEdit = permissions?.can_write ?? hasPerm('can_write');
  const canDelete = permissions?.can_delete ?? hasPerm('can_write');
  const canExport = permissions?.can_export ?? hasPerm('can_export');
  const [dashboardTags, setDashboardTags] = useState<Tag[]>(
    dashboardWithTags.tags || [],
  );
  const { dashboardFolders, refreshDashboardFolders } = useDashboardFolders();
  const [showFolderTagModal, setShowFolderTagModal] = useState(false);
  const [selectedFolderIds, setSelectedFolderIds] = useState<string[]>([]);
  const [isSavingFolderTags, setIsSavingFolderTags] = useState(false);
  const canManageFolders = canEdit;
  const emptyTagDisplay = canEdit ? t('选择分类') : t('无分类');

  useEffect(() => {
    setDashboardTags(dashboardWithTags.tags || []);
  }, [dashboardWithTags.tags]);

  const currentFolders = useMemo(
    () =>
      dashboardFolders
        .filter(folder =>
          folder.items.some(item => item.dashboardId === dashboard.id),
        )
        .map(folder => ({ id: folder.id, name: folder.name })),
    [dashboard.id, dashboardFolders],
  );

  const folderOptions = useMemo(
    () =>
      dashboardFolders.map(folder => ({
        label: folder.name,
        value: folder.id,
      })),
    [dashboardFolders],
  );

  const visibleTags = useMemo(
    () =>
      currentFolders.map(folder => {
        const existingTag = dashboardTags.find(tag => tag.name === folder.name);
        return (
          existingTag ||
          ({
            id: folder.id,
            name: folder.name,
            type: 1,
            toolTipTitle: folder.name,
          } as Tag)
        );
      }),
    [currentFolders, dashboardTags],
  );

  const addDashboardFolderTag = useCallback(async (dashboardId: number, folderName: string) => {
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
  }, [isTaggingEnabled]);

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

  const openFolderTagModal = useCallback(
    async (event?: React.MouseEvent<HTMLSpanElement>) => {
      event?.preventDefault();
      event?.stopPropagation();
      const latestFolders = await refreshDashboardFolders();
      setSelectedFolderIds(
        latestFolders
          .filter(folder =>
            folder.items.some(item => item.dashboardId === dashboard.id),
          )
          .map(folder => folder.id),
      );
      setShowFolderTagModal(true);
    },
    [dashboard.id, refreshDashboardFolders],
  );

  const closeFolderTagModal = useCallback(() => {
    setShowFolderTagModal(false);
    setSelectedFolderIds(currentFolders.map(folder => folder.id));
  }, [currentFolders]);

  const stopModalClickPropagation = useCallback(
    (event: React.MouseEvent<HTMLElement>) => {
      event.preventDefault();
      event.stopPropagation();
    },
    [],
  );

  const saveFolderTags = useCallback(async () => {
    const normalizedNextFolderIds = Array.from(
      new Set(selectedFolderIds.map(id => id.trim()).filter(Boolean)),
    );
    const previousFolderNames = currentFolders.map(folder => folder.name);
    const currentMenuFolderNames = dashboardFolders.map(folder => folder.name);
    const nextFolderNames = dashboardFolders
      .filter(folder => normalizedNextFolderIds.includes(folder.id))
      .map(folder => folder.name);
    const addedFolderNames = nextFolderNames.filter(
      name => !previousFolderNames.includes(name),
    );
    const removedFolderNames = previousFolderNames.filter(
      name => !nextFolderNames.includes(name),
    );
    const staleFolderTagNames = dashboardTags
      .filter(
        tag =>
          (tag.type === 'TagTypes.custom' || tag.type === 1) &&
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
    } catch {
      // ignore toast-less failures here; menu/list state remains unchanged
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
    selectedFolderIds,
  ]);

  const theme = useTheme();
  const menu = (
    <Menu>
      {canDelete && (
        <Menu.Item>
          <div
            role="button"
            tabIndex={0}
            className="action-button"
            onClick={() => onDelete(dashboard)}
            data-test="dashboard-card-option-delete-button"
          >
            <Icons.Trash iconSize="l" /> {t('Delete')}
          </div>
        </Menu.Item>
      )}
      {canExport && (
        <Menu.Item>
          <div
            role="button"
            tabIndex={0}
            onClick={() => handleBulkDashboardExport([dashboard])}
            className="action-button"
            data-test="dashboard-card-option-export-button"
          >
            <Icons.Share iconSize="l" /> {t('Export')}
          </div>
        </Menu.Item>
      )}
      {canEdit && openDashboardEditModal && (
        <Menu.Item>
          <div
            role="button"
            tabIndex={0}
            className="action-button"
            onClick={() => openDashboardEditModal?.(dashboard)}
            data-test="dashboard-card-option-edit-button"
          >
            <Icons.EditAlt iconSize="l" data-test="edit-alt" /> {t('Edit')}
          </div>
        </Menu.Item>
      )}
    </Menu>
  );
  return (
    <StyledCardStyles
      onClick={() => {
        if (!bulkSelectEnabled && !showFolderTagModal) {
          history.push(dashboard.url);
        }
      }}
    >
      <ListViewCard
        loading={dashboard.loading || false}
        title={dashboard.dashboard_title}
        certifiedBy={dashboard.certified_by}
        certificationDetails={dashboard.certification_details}
        // cover={
        //   !isFeatureEnabled(FeatureFlag.THUMBNAILS) || !showThumbnails ? (
        //     <></>
        //   ) : null
        // }
        url={bulkSelectEnabled ? undefined : dashboard.url}
        linkComponent={Link}
        // imgURL={dashboard.thumbnail_url}
        imgFallbackURL="/static/assets/images/dashboard-list-icon.svg"
        description={
          <CardMetaRow>
            <span className="card-meta-left">
              {`${dashboard.changed_on_delta_humanized}`}
            </span>
            <span className="card-meta-right">
              {visibleTags.length ? (
                <TagsList
                  tags={visibleTags.map(tag => ({
                    ...tag,
                    onClick: openFolderTagModal,
                  }))}
                  maxTags={3}
                />
              ) : (
                <EmptyFolderTagTrigger
                  clickable={canManageFolders}
                  role={canManageFolders ? 'button' : undefined}
                  tabIndex={canManageFolders ? 0 : undefined}
                  onClick={canManageFolders ? openFolderTagModal : undefined}
                  onKeyDown={
                    canManageFolders
                      ? event => {
                          if (event.key === 'Enter' || event.key === ' ') {
                            openFolderTagModal(
                              event as unknown as React.MouseEvent<HTMLSpanElement>,
                            );
                          }
                        }
                      : undefined
                  }
                >
                  {emptyTagDisplay}
                </EmptyFolderTagTrigger>
              )}
            </span>
          </CardMetaRow>
        }
        coverLeft={<FacePile users={dashboard.owners || []} />}
        actions={
          <ListViewCard.Actions
            onClick={e => {
              e.stopPropagation();
              e.preventDefault();
            }}
          >
            {userId && (
              <FaveStar
                itemId={dashboard.id}
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
            ariaLabel="dashboard-folder-tags"
            mode="multiple"
            options={folderOptions}
            value={selectedFolderIds}
            onChange={value => setSelectedFolderIds(value as string[])}
            placeholder={t('请选择所属分类')}
          />
        </FolderTagModalContent>
      </Modal>
    </StyledCardStyles>
  );
}

export default DashboardCard;
