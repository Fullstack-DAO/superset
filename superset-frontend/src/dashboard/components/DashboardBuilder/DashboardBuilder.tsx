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
/* eslint-env browser */
import cx from 'classnames';
import React, {
  FC,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import Button from 'src/components/Button';  // 添加这行
import {
  css,
  isFeatureEnabled,
  FeatureFlag,
  JsonObject,
  styled,
  t,
  useTheme,
  useElementOnScreen,
} from '@superset-ui/core';
import { Global } from '@emotion/react';
import { useDispatch, useSelector } from 'react-redux';
import ErrorBoundary from 'src/components/ErrorBoundary';
import BuilderComponentPane from 'src/dashboard/components/BuilderComponentPane';
import DashboardHeader from 'src/dashboard/containers/DashboardHeader';
import Icons from 'src/components/Icons';
import IconButton from 'src/dashboard/components/IconButton';
import DragDroppable from 'src/dashboard/components/dnd/DragDroppable';
import DashboardComponent from 'src/dashboard/containers/DashboardComponent';
import WithPopoverMenu from 'src/dashboard/components/menu/WithPopoverMenu';
import getDirectPathToTabIndex from 'src/dashboard/util/getDirectPathToTabIndex';
import { URL_PARAMS } from 'src/constants';
import { getUrlParam } from 'src/utils/urlUtils';
import {
  DashboardLayout,
  FilterBarOrientation,
  RootState,
} from 'src/dashboard/types';
import {
  setDirectPathToChild,
  setEditMode,
} from 'src/dashboard/actions/dashboardState';
import {
  deleteTopLevelTabs,
  handleComponentDrop,
} from 'src/dashboard/actions/dashboardLayout';
import {
  DASHBOARD_GRID_ID,
  DASHBOARD_ROOT_DEPTH,
  DASHBOARD_ROOT_ID,
  DashboardStandaloneMode,
} from 'src/dashboard/util/constants';
import FilterBar from 'src/dashboard/components/nativeFilters/FilterBar';
import Loading from 'src/components/Loading';
import { EmptyStateBig } from 'src/components/EmptyState';
import { useUiConfig } from 'src/components/UiConfigContext';
import ResizableSidebar from 'src/components/ResizableSidebar';
import {
  CLOSED_FILTER_BAR_WIDTH,
  FILTER_BAR_HEADER_HEIGHT,
  MAIN_HEADER_HEIGHT,
  OPEN_FILTER_BAR_MAX_WIDTH,
  OPEN_FILTER_BAR_WIDTH,
} from 'src/dashboard/constants';
import { getRootLevelTabsComponent, shouldFocusTabs } from './utils';
import DashboardContainer from './DashboardContainer';
import { useNativeFilters } from './state';
import DashboardWrapper from './DashboardWrapper';
import DashboardCollaboratorModal from '../PropertiesModal/DashboardCollaboratorModal';

type DashboardBuilderProps = {};

// @z-index-above-dashboard-charts + 1 = 11
const FiltersPanel = styled.div<{ width: number; hidden: boolean }>`
  grid-column: 1;
  grid-row: 1 / span 2;
  z-index: 11;
  width: ${({ width }) => width}px;
  ${({ hidden }) => hidden && `display: none;`}
`;

const StickyPanel = styled.div<{ width: number }>`
  position: sticky;
  top: -1px;
  width: ${({ width }) => width}px;
  flex: 0 0 ${({ width }) => width}px;
`;

// @z-index-above-dashboard-popovers (99) + 1 = 100
const StyledHeader = styled.div`
  grid-column: 2;
  grid-row: 1;
  position: sticky;
  top: 0;
  z-index: 100;
  max-width: 100vw;
`;

const StyledContent = styled.div<{
  fullSizeChartId: number | null;
}>`
  grid-column: 2;
  grid-row: 2;
  // @z-index-above-dashboard-header (100) + 1 = 101
  ${({ fullSizeChartId }) => fullSizeChartId && `z-index: 101;`}
`;

const StyledDashboardContent = styled.div<{
  editMode: boolean;
  marginLeft: number;
}>`
  ${({ theme, editMode, marginLeft }) => css`
    display: flex;
    flex-direction: row;
    flex-wrap: nowrap;
    height: auto;
    flex: 1;

    .grid-container {
      width: 0;
      flex: 1;
      position: relative;
      margin: ${theme.gridUnit * 6}px ${theme.gridUnit * 4}px ${theme.gridUnit * 6}px ${marginLeft}px;
      max-width: 100%;

      @media (max-width: 768px) {
        margin: ${theme.gridUnit * 2}px;
        padding: 0;
        width: 100%;
        max-width: none;
        
        // 移动端网格布局调整
        .dashboard-grid {
          display: block;
          width: 100%;
          padding: ${theme.gridUnit * 2}px;
          
          // 确保每个组件都能完整显示
          .dashboard-component-chart-holder {
            width: 100% !important;
            margin-bottom: ${theme.gridUnit * 4}px;
          }
        }
      }
    }
  `}
`;

const TopButtons = styled.div`
  display: flex;
  justify-content: flex-end;
  align-items: center;
  gap: ${({ theme }) => theme.gridUnit * 2}px;
  padding: ${({ theme }) => theme.gridUnit * 2}px;
`;

const DashboardBuilder: FC<DashboardBuilderProps> = () => {
  const dispatch = useDispatch();
  const uiConfig = useUiConfig();
  const theme = useTheme();

  const dashboardId = useSelector<RootState, number>(
    ({ dashboardInfo }) => Number(dashboardInfo.id),
  );
  const dashboardLayout = useSelector<RootState, DashboardLayout>(
    state => state.dashboardLayout.present,
  );
  const editMode = useSelector<RootState, boolean>(
    state => state.dashboardState.editMode,
  );
  const canEdit = useSelector<RootState, boolean>(
    ({ dashboardInfo }) => dashboardInfo.dash_edit_perm,
  );
  const dashboardIsSaving = useSelector<RootState, boolean>(
    ({ dashboardState }) => dashboardState.dashboardIsSaving,
  );
  const fullSizeChartId = useSelector<RootState, number | null>(
    state => state.dashboardState.fullSizeChartId,
  );
  const crossFiltersEnabled = isFeatureEnabled(
    FeatureFlag.DASHBOARD_CROSS_FILTERS,
  );
  const filterBarOrientation = useSelector<RootState, FilterBarOrientation>(
    ({ dashboardInfo }) =>
      isFeatureEnabled(FeatureFlag.HORIZONTAL_FILTER_BAR)
        ? dashboardInfo.filterBarOrientation
        : FilterBarOrientation.VERTICAL,
  );

  const handleChangeTab = useCallback(
    ({ pathToTabIndex }: { pathToTabIndex: string[] }) => {
      dispatch(setDirectPathToChild(pathToTabIndex));
    },
    [dispatch],
  );

  const handleDeleteTopLevelTabs = useCallback(() => {
    dispatch(deleteTopLevelTabs());

    const firstTab = getDirectPathToTabIndex(
      getRootLevelTabsComponent(dashboardLayout),
      0,
    );
    dispatch(setDirectPathToChild(firstTab));
  }, [dashboardLayout, dispatch]);

  const handleDrop = useCallback(
    dropResult => dispatch(handleComponentDrop(dropResult)),
    [dispatch],
  );

  const headerRef = React.useRef<HTMLDivElement>(null);
  const dashboardRoot = dashboardLayout[DASHBOARD_ROOT_ID];
  const rootChildId = dashboardRoot?.children[0];
  const topLevelTabs =
    rootChildId !== DASHBOARD_GRID_ID
      ? dashboardLayout[rootChildId]
      : undefined;
  const standaloneMode = getUrlParam(URL_PARAMS.standalone);
  const isReport = standaloneMode === DashboardStandaloneMode.REPORT;
  const hideDashboardHeader =
    uiConfig.hideTitle ||
    standaloneMode === DashboardStandaloneMode.HIDE_NAV_AND_TITLE ||
    isReport;

  const [barTopOffset, setBarTopOffset] = useState(0);
  const [isCollaboratorsModalVisible, setCollaboratorsModalVisible] = useState(false);

  useEffect(() => {
    setBarTopOffset(headerRef.current?.getBoundingClientRect()?.height || 0);

    let observer: ResizeObserver;
    if (global.hasOwnProperty('ResizeObserver') && headerRef.current) {
      observer = new ResizeObserver(entries => {
        setBarTopOffset(
          current => entries?.[0]?.contentRect?.height || current,
        );
      });

      observer.observe(headerRef.current);
    }

    return () => {
      observer?.disconnect();
    };
  }, []);

  const {
    showDashboard,
    dashboardFiltersOpen,
    toggleDashboardFiltersOpen,
    nativeFiltersEnabled,
  } = useNativeFilters();

  const [containerRef, isSticky] = useElementOnScreen<HTMLDivElement>({
    threshold: [1],
  });

  const showFilterBar =
    (crossFiltersEnabled || nativeFiltersEnabled) && !editMode;

  const offset =
    FILTER_BAR_HEADER_HEIGHT +
    (isSticky || standaloneMode ? 0 : MAIN_HEADER_HEIGHT);

  const filterBarHeight = `calc(100vh - ${offset}px)`;
  const filterBarOffset = dashboardFiltersOpen ? 0 : barTopOffset + 20;

  const draggableStyle = useMemo(
    () => ({
      marginLeft:
        dashboardFiltersOpen ||
        editMode ||
        !nativeFiltersEnabled ||
        filterBarOrientation === FilterBarOrientation.HORIZONTAL
          ? 0
          : -32,
    }),
    [
      dashboardFiltersOpen,
      editMode,
      filterBarOrientation,
      nativeFiltersEnabled,
    ],
  );

  // If a new tab was added, update the directPathToChild to reflect it
  const currentTopLevelTabs = useRef(topLevelTabs);
  useEffect(() => {
    const currentTabsLength = currentTopLevelTabs.current?.children?.length;
    const newTabsLength = topLevelTabs?.children?.length;

    if (
      currentTabsLength !== undefined &&
      newTabsLength !== undefined &&
      newTabsLength > currentTabsLength
    ) {
      const lastTab = getDirectPathToTabIndex(
        getRootLevelTabsComponent(dashboardLayout),
        newTabsLength - 1,
      );
      dispatch(setDirectPathToChild(lastTab));
    }

    currentTopLevelTabs.current = topLevelTabs;
  }, [topLevelTabs]);

  const renderDraggableContent = useCallback(
    ({ dropIndicatorProps }: { dropIndicatorProps: JsonObject }) => (
      <div>
        {!hideDashboardHeader && <DashboardHeader />}
        {showFilterBar &&
          filterBarOrientation === FilterBarOrientation.HORIZONTAL && (
            <FilterBar
              orientation={FilterBarOrientation.HORIZONTAL}
              hidden={isReport}
            />
          )}
        {dropIndicatorProps && <div {...dropIndicatorProps} />}
        {!isReport && topLevelTabs && !uiConfig.hideNav && (
          <WithPopoverMenu
            shouldFocus={shouldFocusTabs}
            menuItems={[
              <IconButton
                icon={<Icons.FallOutlined iconSize="xl" />}
                label={t('Collapse tab content')}
                onClick={handleDeleteTopLevelTabs}
              />,
            ]}
            editMode={editMode}
          >
            {/* @ts-ignore */}
            <DashboardComponent
              id={topLevelTabs?.id}
              parentId={DASHBOARD_ROOT_ID}
              depth={DASHBOARD_ROOT_DEPTH + 1}
              index={0}
              renderTabContent={false}
              renderHoverMenu={false}
              onChangeTab={handleChangeTab}
            />
          </WithPopoverMenu>
        )}
      </div>
    ),
    [
      nativeFiltersEnabled,
      filterBarOrientation,
      editMode,
      handleChangeTab,
      handleDeleteTopLevelTabs,
      hideDashboardHeader,
      isReport,
      topLevelTabs,
      uiConfig.hideNav,
    ],
  );

  const dashboardContentMarginLeft =
    !dashboardFiltersOpen &&
    !editMode &&
    nativeFiltersEnabled &&
    filterBarOrientation !== FilterBarOrientation.HORIZONTAL
      ? 0
      : theme.gridUnit * 8;

  return (
    <DashboardWrapper>
      {showFilterBar && filterBarOrientation === FilterBarOrientation.VERTICAL && (
        <>
          <ResizableSidebar
            id={`dashboard:${dashboardId}`}
            enable={dashboardFiltersOpen}
            minWidth={OPEN_FILTER_BAR_WIDTH}
            maxWidth={OPEN_FILTER_BAR_MAX_WIDTH}
            initialWidth={OPEN_FILTER_BAR_WIDTH}
          >
            {adjustedWidth => {
              const filterBarWidth = dashboardFiltersOpen
                ? adjustedWidth
                : CLOSED_FILTER_BAR_WIDTH;
              return (
                <FiltersPanel
                  width={filterBarWidth}
                  hidden={isReport}
                  data-test="dashboard-filters-panel"
                >
                  <StickyPanel ref={containerRef} width={filterBarWidth}>
                    <ErrorBoundary>
                      <FilterBar
                        orientation={FilterBarOrientation.VERTICAL}
                        verticalConfig={{
                          filtersOpen: dashboardFiltersOpen,
                          toggleFiltersBar: toggleDashboardFiltersOpen,
                          width: filterBarWidth,
                          height: filterBarHeight,
                          offset: filterBarOffset,
                        }}
                      />
                    </ErrorBoundary>
                  </StickyPanel>
                </FiltersPanel>
              );
            }}
          </ResizableSidebar>
        </>
      )}
      <StyledHeader ref={headerRef}>
        <TopButtons>
          <Button
            buttonStyle="secondary"
            onClick={() => setCollaboratorsModalVisible(true)}
            className="manage-collaborators"
          >
            {t('管理协作者')}
          </Button>
        </TopButtons>
        <DragDroppable
          component={dashboardRoot}
          parentComponent={null}
          depth={DASHBOARD_ROOT_DEPTH}
          index={0}
          orientation="column"
          onDrop={handleDrop}
          editMode={editMode}
          disableDragDrop={!!topLevelTabs}
          style={draggableStyle}
        >
          {renderDraggableContent}
        </DragDroppable>
      </StyledHeader>
      <StyledContent fullSizeChartId={fullSizeChartId}>
        <Global
          styles={css`
            // @z-index-above-dashboard-header (100) + 1 = 101
            ${fullSizeChartId &&
            `div > .filterStatusPopover.ant-popover{z-index: 101}`}
          `}
        />
        {!editMode &&
          !topLevelTabs &&
          dashboardLayout[DASHBOARD_GRID_ID]?.children?.length === 0 && (
            <EmptyStateBig
              title={t('There are no charts added to this dashboard')}
              description={
                canEdit &&
                t(
                  'Go to the edit mode to configure the dashboard and add charts',
                )
              }
              buttonText={canEdit && t('Edit the dashboard')}
              buttonAction={() => dispatch(setEditMode(true))}
              image="dashboard.svg"
            />
          )}
        <StyledDashboardContent
          data-test="dashboard-content-wrapper"
          className={cx('dashboard', editMode && 'dashboard--editing')}
          editMode={editMode}
          marginLeft={dashboardContentMarginLeft}
        >
          <StyledDashboardContent
            className="dashboard-content"
            editMode={editMode}
            marginLeft={dashboardContentMarginLeft}
          >
            {showDashboard ? (
              <DashboardContainer topLevelTabs={topLevelTabs} />
            ) : (
              <Loading />
            )}
            {editMode && <BuilderComponentPane topOffset={barTopOffset} />}
          </StyledDashboardContent>
        </StyledDashboardContent>
      </StyledContent>
      {dashboardIsSaving && (
        <Loading
          css={css`
            && {
              position: fixed;
            }
          `}
        />
      )}
      <DashboardCollaboratorModal
        visible={isCollaboratorsModalVisible}
        onClose={() => setCollaboratorsModalVisible(false)}
        dashboardId={dashboardId}
      />
    </DashboardWrapper>
  );
};

export default DashboardBuilder;
