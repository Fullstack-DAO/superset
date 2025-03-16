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
import {
  addAlpha,
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
import Button from 'src/components/Button';  // 添加这行
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
  BUILDER_SIDEPANEL_WIDTH,
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
import DashboardCollaboratorModal from "../PropertiesModal/DashboardCollaboratorModal";

new Date().getTime();
type DashboardBuilderProps = {};

// @z-index-above-dashboard-charts + 1 = 11
const FiltersPanel = styled.div<{ width: number; hidden: boolean }>`
  grid-column: 1;
  grid-row: 1 / span 2;
  z-index: 11;
  width: ${({ width }) => width}px;
  ${({ hidden }) => hidden && `display: none;`}

  @media (max-width: 768px) {
    opacity: 0 !important;
    visibility: hidden !important;
    pointer-events: none !important;
    position: absolute !important;
    width: 0 !important;
  }
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

  @media (max-width: 768px) {
    position: relative;
    width: 100%;
    padding: 0;
    margin: 0;
    
    /* 重置所有容器样式 */
    & > div {
      width: 100% !important;
      margin: 0 !important;
      padding: 0 !important;
    }

    /* 调整标题容器布局 */
    .dashboard-header {
      position: relative !important;
      width: 100% !important;
      padding: 8px 16px !important;
      margin: 0 !important;
      display: block !important;
      
      .dashboard-component-header {
        display: block !important;
        width: 100% !important;
        padding: 0 !important;
        margin: 0 !important;
      }

      .header-large {
        display: block !important;
        width: 100% !important;
        padding: 0 !important;
        margin: 0 !important;
      }

      /* 优化标题显示 */
      .header-title,
      .dashboard__title,
      .dashboard-title,
      span[role="button"].editable-title,
      div.editable-title,
      h1 {
        display: block !important;
        width: 100% !important;
        max-width: none !important;
        padding: 4px 0 !important;
        margin: 0 !important;
        text-align: left !important;
        white-space: normal !important;
        word-break: break-word !important;
        overflow: visible !important;
        text-overflow: clip !important;
        font-size: 18px !important;
        line-height: 1.4 !important;
        position: static !important;
        transform: none !important;
        left: auto !important;
      }

      /* 移除所有可能影响布局的绝对定位元素 */
      .header-with-actions {
        position: static !important;
        width: 100% !important;
        padding: 0 !important;
        margin: 0 !important;
        
        & > * {
          position: static !important;
          transform: none !important;
        }
      }

      /* 隐藏其他按钮和元素 */
      .navbar-nav,
      .navbar-right,
      .top-nav-menu,
      .navbar-brand-text,
      .navbar-static-side,
      .nav-item,
      .sidebar,
      .sidebar-nav,
      .navbar-default,
      [data-test="navbar-top"],
      [data-test="navbar-brand-wrapper"],
      [data-test="navbar-right-wrapper"],
      .main-menu,
      #app-menu,
      .nav-item .dropdown-menu,
      .navbar .dropdown-menu,
      .navbar-nav > li,
      .navbar-nav > li > a,
      .nav-link,
      .dashboard-header__actions,
      .dashboard-header__actions *,
      [data-test="dashboard-header-buttons"],
      [data-test="dashboard-header-buttons"] *,
      .ant-dropdown-trigger,
      .header-with-actions button,
      button[data-test="edit-dashboard"],
      button[data-test="dashboard-edit-actions"],
      .edit-button,
      .dashboard-builder-sidepane-trigger,
      .more-horiz,
      .ant-btn:not(.dashboard-title),
      .button-container,
      .action-buttons,
      .css-1t062t8,
      .css-16uq7e2,
      div[role="button"]:not(.dashboard-title),
      span[role="button"]:not(.dashboard-title) {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
        width: 0 !important;
        height: 0 !important;
        padding: 0 !important;
        margin: 0 !important;
        border: 0 !important;
        position: absolute !important;
        left: -9999px !important;
      }

      /* 特别针对 logo 的样式 */
      .navbar-brand {
        padding: 0 !important;
        margin: 4px !important;
        max-height: 32px !important;
        
        img {
          height: 16px !important;  /* 显著减小 logo 高度 */
          width: auto !important;
          max-width: 80px !important;  /* 减小最大宽度 */
          object-fit: contain !important;
        }
      }

      /* 调整顶部导航栏高度 */
      .dashboard-header {
        min-height: 36px !important;
        height: auto !important;
        padding: 4px 8px !important;
      }
    }
  }
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

    .grid-container .dashboard-component-tabs {
      box-shadow: none;
      padding-left: 0;
    }

    .grid-container {
      width: 0;
      flex: 1;
      position: relative;
      margin-top: ${theme.gridUnit * 6}px;
      margin-right: ${theme.gridUnit * 8}px;
      margin-bottom: ${theme.gridUnit * 6}px;
      margin-left: ${marginLeft}px;

      ${editMode &&
        `max-width: calc(100% - ${BUILDER_SIDEPANEL_WIDTH + theme.gridUnit * 16}px);`
      }

      @media (max-width: 768px) {
        margin: ${theme.gridUnit * 2}px;
        
        .dashboard-grid {
          display: flex !important;
          flex-direction: column !important;
        }
        
        .dashboard-grid > div {
          width: 100% !important;
          margin-bottom: ${theme.gridUnit * 4}px;
        }

        .dashboard-component-chart-holder {
          width: 100% !important;
          height: auto !important;
          margin-bottom: ${theme.gridUnit * 4}px !important;
        }

        .grid-column,
        .grid-row {
          width: 100% !important;
          display: block !important;
        }

        .chart-container {
          width: 100% !important;
          min-height: 400px !important;
        }

        .slice_container {
          transform: none !important;
          font-size: 14px !important;
        }

        .filter-bar {
          flex-direction: column;
          padding: ${theme.gridUnit * 2}px;
        }
        
        .filter-bar .filter-item {
          width: 100%;
          margin-bottom: ${theme.gridUnit * 2}px;
        }

        .dashboard-component {
          margin-bottom: ${theme.gridUnit * 4}px !important;
        }

        .dragdroppable-row {
          display: block !important;
        }
        
        .dragdroppable-row > div {
          width: 100% !important;
          margin-bottom: ${theme.gridUnit * 4}px;
        }

        .resizable-container {
          width: 100% !important;
          height: auto !important;
          min-height: 400px;
          resize: none !important;
        }

        /* Hide specific elements on mobile */
        .navbar-right [data-test="new-dropdown"],
        .navbar-right [href*="/chart/add"],
        .navbar-right [href*="/dashboard/new"],
        .navbar-right [href*="/dashboard/list"],
        .navbar-right [href*="/chart/list"],
        .navbar-right [data-test="new-dropdown"],
        .navbar-right [href*="copilot"],
        .navbar-right [href*="sqllab"],
        .navbar-right [href*="workflow"],
        .navbar-right .manage-collaborators,
        .dashboard-builder-sidepane,
        .dashboard-component-tabs {
          display: none !important;
        }

        /* Adjust header for mobile */
        .dashboard-header {
          flex-direction: column;
          padding: ${theme.gridUnit * 2}px;
          
          .header-large {
            flex-direction: column;
            align-items: flex-start;
          }
        }

        /* Ensure content takes full width */
        .grid-container {
          margin: ${theme.gridUnit * 2}px !important;
          width: calc(100% - ${theme.gridUnit * 4}px) !important;
        }
      }
    }

    .dashboard-builder-sidepane {
      width: ${BUILDER_SIDEPANEL_WIDTH}px;
      z-index: 1;
    }

    .dashboard-component-chart-holder {
      width: 100%;
      height: 100%;
      background-color: ${theme.colors.grayscale.light5};
      position: relative;
      padding: ${theme.gridUnit * 4}px;
      overflow-y: visible;

      // transitionable traits to show filter relevance
      transition: opacity ${theme.transitionTiming}s ease-in-out,
        border-color ${theme.transitionTiming}s ease-in-out,
        box-shadow ${theme.transitionTiming}s ease-in-out;

      &.fade-in {
        border-radius: ${theme.borderRadius}px;
        box-shadow: inset 0 0 0 2px ${theme.colors.primary.base},
          0 0 0 3px
            ${addAlpha(theme.colors.primary.base, parseFloat(theme.opacity.light) / 100)};
      }

      &.fade-out {
        border-radius: ${theme.borderRadius}px;
        box-shadow: none;
      }

      & .missing-chart-container {
        display: flex;
        flex-direction: column;
        align-items: center;
        overflow-y: auto;
        justify-content: center;

        .missing-chart-body {
          font-size: ${theme.typography.sizes.s}px;
          position: relative;
          display: flex;
        }
      }
    }
  `}
`;

const HeaderButtons = styled.div`
  display: flex;
  align-items: center;
  gap: ${({ theme }) => theme.gridUnit * 6}px;  // 48px 间距
  position: absolute;
  right: ${({ theme }) => theme.gridUnit * 58}px; // 将56改为58，向左平移2px
  top: 50%;
  transform: translateY(-50%);
  z-index: 99;

  @media (max-width: 768px) {
    display: none !important;  // 在移动端完全隐藏管理协作者按钮
  }
`;

const mobileStyles = css`
  @media (max-width: 768px) {
    html body #app {
      /* 只隐藏编辑按钮和更多操作按钮 */
      button[data-test="edit-dashboard"],
      button[data-test="dashboard-edit-actions"],
      .dashboard-header__actions,
      .dashboard-header__actions *,
      .edit-dashboard-button,
      .more-horiz,
      .ant-dropdown-trigger,
      [data-test="dashboard-header-buttons"],
      [aria-label="More Options"],
      .more-actions,
      button[aria-label="more"],
      .more-menu-trigger,
      [data-test="more-actions"],
      .header-with-actions button,
      .header-with-actions .button-container,
      .header-with-actions .action-buttons,
      .manage-collaborators {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
        width: 0 !important;
        height: 0 !important;
        padding: 0 !important;
        margin: 0 !important;
        pointer-events: none !important;
      }

      /* 确保标题容器正常显示 */
      .dashboard-header {
        position: relative !important;
        width: 100% !important;
        padding: 8px 16px !important;
        margin: 0 !important;
        display: block !important;
      }

      /* 确保标题文本正常显示 */
      .dashboard-title,
      .header-title,
      .dashboard__title,
      h1.dashboard-title {
        display: block !important;
        font-size: 20px !important;
        line-height: 1.4 !important;
        padding: 8px !important;
        margin: 0 !important;
        text-align: left !important;
      }
    }

    /* 隐藏导航标签和菜单，但保留 logo */
    html body #app .navbar-default,
    html body #app [data-test="navbar-top"],
    html body #app .navbar {
      /* 导航菜单项 */
      .navbar-nav:not(.navbar-brand),
      .nav-item:not(.navbar-brand),
      .top-nav-menu,
      [role="navigation"] > *:not(.navbar-brand),
      [data-test="navbar-list-menu"],
      .dropdown-menu,
      a[href*="/dashboard"]:not(.navbar-brand),
      a[href*="/chart"]:not(.navbar-brand),
      a[href*="/dataset"]:not(.navbar-brand),
      a[href*="/sqllab"]:not(.navbar-brand),
      a[href*="/copilot"]:not(.navbar-brand),
      a[href*="/workflow"]:not(.navbar-brand),
      a[href*="/docs"]:not(.navbar-brand),
      .ant-menu,
      .ant-menu-item,
      .menu-item,
      .dropdown,
      .dropdown-toggle,
      .navbar-right:not(.navbar-brand),
      .top-menu-item:not(.navbar-brand),
      [role="menuitem"]:not(.navbar-brand),
      [role="menu"]:not(.navbar-brand),
      [data-test="menu-item"],
      [data-test="navbar-list-menu"],
      .nav-links,
      .menu-links,
      [href*="datasets"],
      [href*="sql"],
      [href*="copilot"],
      [href*="docs"],
      .nav > li:not(.navbar-brand),
      .navbar-nav > li:not(.navbar-brand) {
        display: none !important;
        visibility: hidden !important;
        opacity: 0 !important;
        width: 0 !important;
        height: 0 !important;
        padding: 0 !important;
        margin: 0 !important;
        pointer-events: none !important;
        position: absolute !important;
        left: -9999px !important;
      }

      /* 确保 logo 显示 */
      .navbar-brand {
        display: block !important;
        visibility: visible !important;
        opacity: 1 !important;
        width: auto !important;
        height: 50px !important;
        padding: 8px 16px !important;
        margin: 0 !important;
        
        img {
          display: block !important;
          height: 32px !important;
          width: auto !important;
          max-width: 120px !important;
        }
      }
    }
  }
`;

const DashboardContentWrapper = styled.div`
  display: flex;
  flex-direction: column;
  flex-grow: 1;
  position: relative;
  height: 100%;
  
  @media (max-width: 768px) {
    margin: 0;
    padding: 0;
    width: 100%;
    
    .dashboard-content {
      margin: 0 !important;
      padding: 8px !important;
    }
  }
`;

const DashboardBuilder: FC<DashboardBuilderProps> = () => {
  const dispatch = useDispatch();
  const uiConfig = useUiConfig();
  const theme = useTheme();

  const [isCollaboratorsModalVisible, setCollaboratorsModalVisible] = useState(false);
  const dashboardId = useSelector<RootState, number>(
    ({ dashboardInfo }) => dashboardInfo.id,
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
        {!hideDashboardHeader && (
          <div style={{ position: 'relative' }}>
            <DashboardHeader />
            <HeaderButtons>
              <Button
                buttonStyle="secondary"
                onClick={() => setCollaboratorsModalVisible(true)}
                className="manage-collaborators"
              >
                {t('管理协作者')}
              </Button>
            </HeaderButtons>
          </div>
        )}
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
      <Global styles={mobileStyles} />
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
        {/* @ts-ignore */}
        <DragDroppable
          data-test="top-level-tabs"
          component={dashboardRoot}
          parentComponent={null}
          depth={DASHBOARD_ROOT_DEPTH}
          index={0}
          orientation="column"
          onDrop={handleDrop}
          editMode={editMode}
          // you cannot drop on/displace tabs if they already exist
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
        <DashboardContentWrapper
          data-test="dashboard-content-wrapper"
          className={cx('dashboard', editMode && 'dashboard--editing')}
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
        </DashboardContentWrapper>
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
