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
import React from 'react';
import PropTypes from 'prop-types';
import classNames from 'classnames';
import { addAlpha, css, styled, t } from '@superset-ui/core';
import { EmptyStateBig } from 'src/components/EmptyState';
import { componentShape } from '../util/propShapes';
import DashboardComponent from '../containers/DashboardComponent';
import DragDroppable from './dnd/DragDroppable';
import { GRID_GUTTER_SIZE, GRID_COLUMN_COUNT } from '../util/constants';
import { TAB_TYPE } from '../util/componentTypes';

const propTypes = {
  depth: PropTypes.number.isRequired,
  editMode: PropTypes.bool,
  gridComponent: componentShape,
  handleComponentDrop: PropTypes.func.isRequired,
  isComponentVisible: PropTypes.bool.isRequired,
  resizeComponent: PropTypes.func.isRequired,
  setDirectPathToChild: PropTypes.func.isRequired,
  width: PropTypes.number.isRequired,
  dashboardId: PropTypes.number,
};

const defaultProps = {};

const renderDraggableContentBottom = dropProps =>
  dropProps.dropIndicatorProps && (
    <div className="drop-indicator drop-indicator--bottom" />
  );

const renderDraggableContentTop = dropProps =>
  dropProps.dropIndicatorProps && (
    <div className="drop-indicator drop-indicator--top" />
  );

// 删除第一个定义
// const DashboardEmptyStateContainer = styled.div`
//   position: absolute;
//   top: 0;
//   bottom: 0;
//   left: 0;
//   right: 0;
// `;

const GridContent = styled.div`
  ${({ theme }) => css`
    display: flex;
    flex-direction: column;
    height: auto;
    max-height: 100%;
    overflow-y: auto;
    font-size: 16px;

    /* 添加图表标题样式 */
    .chart-header {
      padding: ${theme.gridUnit * 2}px;
      font-size: ${theme.typography.sizes.m}px;
      line-height: 1.4;
      font-weight: ${theme.typography.weights.bold};
      margin-bottom: ${theme.gridUnit * 2}px;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }

    /* gutters between rows */
    & > div:not(:last-child):not(.empty-droptarget) {
      margin-bottom: ${theme.gridUnit * 6}px;
      padding: ${theme.gridUnit * 4}px;
    }

    // 移动端样式调整
    @media (max-width: 768px) {
      font-size: 14px;
      
      .chart-header {
        font-size: ${theme.typography.sizes.s}px;
        padding: ${theme.gridUnit}px;
      }
    }

    & > div:not(:last-child):not(.empty-droptarget) {
      margin-bottom: ${theme.gridUnit * 4}px;
      padding: ${theme.gridUnit * 2}px;
    }

    & > .empty-droptarget {
      width: 100%;
      height: 100%;
    }

    & > .empty-droptarget:first-child {
      height: ${theme.gridUnit * 12}px;
      margin-top: ${theme.gridUnit * -6}px;
    }

    & > .empty-droptarget:last-child {
      height: ${theme.gridUnit * 12}px;
      margin-top: ${theme.gridUnit * -6}px;
    }

    & > .empty-droptarget.empty-droptarget--full:only-child {
      height: 80vh;
    }
  `}
`;

// 调整空状态容器样式
const DashboardEmptyStateContainer = styled.div`
  position: relative;
  min-height: 200px;
  padding: 32px;
  font-size: 16px;
  line-height: 1.5;
  display: flex;
  align-items: center;
  justify-content: center;
  background: ${({ theme }) => theme.colors.grayscale.light5};
  border-radius: 4px;
  margin: 16px;
  box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
`;

const GridColumnGuide = styled.div`
  ${({ theme }) => css`
    // /* Editing guides */
    &.grid-column-guide {
      position: absolute;
      top: 0;
      min-height: 100%;
      background-color: ${addAlpha(
        theme.colors.primary.base,
        parseFloat(theme.opacity.light) / 100,
      )};
      pointer-events: none;
      box-shadow: inset 0 0 0 1px
        ${addAlpha(
          theme.colors.primary.base,
          parseFloat(theme.opacity.mediumHeavy) / 100,
        )};
    }
  `};
`;

// 添加移动端网格配置
// 修改移动端网格配置
const MOBILE_GRID_SETTINGS = {
  columnCount: 12,  // 改为12列，与默认的 GRID_COLUMN_COUNT 保持一致
  gutterSize: 8,
  rowHeight: 40,
  minWidth: 320,
};

// 添加移动设备检测函数
const isMobileDevice = () => {
  return window.innerWidth <= 768;
};

class DashboardGrid extends React.PureComponent {
  constructor(props) {
    super(props);
    this.state = {
      isResizing: false,
      isMobile: false,  // 添加移动设备状态
    };

    this.handleResizeStart = this.handleResizeStart.bind(this);
    this.handleResizeStop = this.handleResizeStop.bind(this);
    this.handleTopDropTargetDrop = this.handleTopDropTargetDrop.bind(this);
    this.getRowGuidePosition = this.getRowGuidePosition.bind(this);
    this.setGridRef = this.setGridRef.bind(this);
    this.handleChangeTab = this.handleChangeTab.bind(this);
  }

  getRowGuidePosition(resizeRef) {
    if (resizeRef && this.grid) {
      return (
        resizeRef.getBoundingClientRect().bottom -
        this.grid.getBoundingClientRect().top -
        2
      );
    }
    return null;
  }

  setGridRef(ref) {
    this.grid = ref;
  }

  handleResizeStart() {
    this.setState(() => ({
      isResizing: true,
    }));
  }

  handleResizeStop({ id, widthMultiple: width, heightMultiple: height }) {
    this.props.resizeComponent({ id, width, height });

    this.setState(() => ({
      isResizing: false,
    }));
  }

  handleTopDropTargetDrop(dropResult) {
    if (dropResult) {
      this.props.handleComponentDrop({
        ...dropResult,
        destination: {
          ...dropResult.destination,
          // force appending as the first child if top drop target
          index: 0,
        },
      });
    }
  }

  handleChangeTab({ pathToTabIndex }) {
    this.props.setDirectPathToChild(pathToTabIndex);
  }

  componentDidMount() {
    // 直接使用 props 中的 width 判断
    this.setState({ isMobile: this.props.width <= 768 });
    
    // 添加窗口大小变化监听
    window.addEventListener('resize', this.handleResize);
  }

  componentWillUnmount() {
    // 移除监听器
    window.removeEventListener('resize', this.handleResize);
  }

  // 添加 resize 处理函数
  handleResize = () => {
    this.setState({ isMobile: window.innerWidth <= 768 });
  };

  render() {
    const { isResizing, isMobile } = this.state;
    const {
      width,
      gridComponent,  // 添加 gridComponent
      handleComponentDrop,
      depth,
      isComponentVisible,
      editMode,
      canEdit,
      setEditMode,
      dashboardId,
    } = this.props;
    
    // 修改宽度计算逻辑
    const effectiveWidth = Math.max(width, MOBILE_GRID_SETTINGS.minWidth);
    const columnCount = isMobile ? 1 : GRID_COLUMN_COUNT;
    const gutterSize = isMobile ? MOBILE_GRID_SETTINGS.gutterSize : GRID_GUTTER_SIZE;
    
    // 调整列宽计算
    const columnPlusGutterWidth = effectiveWidth / columnCount;
    const columnWidth = Math.floor(columnPlusGutterWidth - gutterSize);

    // 修改 DashboardComponent 的 availableColumnCount
    const availableColumnCount = isMobile ? 1 : GRID_COLUMN_COUNT;

    // 移除重复声明
    // const { isResizing } = this.state;  // 删除这行

    const shouldDisplayEmptyState = gridComponent?.children?.length === 0;
    
    const shouldDisplayTopLevelTabEmptyState =
      shouldDisplayEmptyState && gridComponent.type === TAB_TYPE;

    const dashboardEmptyState = editMode && (
      <EmptyStateBig
        title={t('Drag and drop components and charts to the dashboard')}
        description={t(
          'You can create a new chart or use existing ones from the panel on the right',
        )}
        buttonText={
          <>
            <i className="fa fa-plus" />
            {t('Create a new chart')}
          </>
        }
        buttonAction={() => {
          window.open(
            `/chart/add?dashboard_id=${dashboardId}`,
            '_blank',
            'noopener noreferrer',
          );
        }}
        image="chart.svg"
      />
    );

    const topLevelTabEmptyState = editMode ? (
      <EmptyStateBig
        title={t('Drag and drop components to this tab')}
        description={t(
          `You can create a new chart or use existing ones from the panel on the right`,
        )}
        buttonText={
          <>
            <i className="fa fa-plus" />
            {t('Create a new chart')}
          </>
        }
        buttonAction={() => {
          window.open(
            `/chart/add?dashboard_id=${dashboardId}`,
            '_blank',
            'noopener noreferrer',
          );
        }}
        image="chart.svg"
      />
    ) : (
      <EmptyStateBig
        title={t('There are no components added to this tab')}
        description={
          canEdit && t('You can add the components in the edit mode.')
        }
        buttonText={canEdit && t('Edit the dashboard')}
        buttonAction={
          canEdit &&
          (() => {
            setEditMode(true);
          })
        }
        image="chart.svg"
      />
    );

    return width < 100 ? null : (
      <>
        {shouldDisplayEmptyState && (
          <DashboardEmptyStateContainer>
            {shouldDisplayTopLevelTabEmptyState
              ? topLevelTabEmptyState
              : dashboardEmptyState}
          </DashboardEmptyStateContainer>
        )}
        <div className="dashboard-grid" ref={this.setGridRef}>
          <GridContent className="grid-content" data-test="grid-content">
            {/* make the area above components droppable */}
            {editMode && (
              <DragDroppable
                component={gridComponent}
                depth={depth}
                parentComponent={null}
                index={0}
                orientation="column"
                onDrop={this.handleTopDropTargetDrop}
                className={classNames({
                  'empty-droptarget': true,
                  'empty-droptarget--full':
                    gridComponent?.children?.length === 0,
                })}
                editMode
              >
                {renderDraggableContentTop}
              </DragDroppable>
            )}
            {gridComponent?.children?.map((id, index) => (
              <DashboardComponent
                key={id}
                id={id}
                parentId={gridComponent.id}
                depth={depth + 1}
                index={index}
                availableColumnCount={availableColumnCount}  // 使用新的 availableColumnCount
                columnWidth={columnWidth}
                isComponentVisible={isComponentVisible}
                onResizeStart={this.handleResizeStart}
                onResize={this.handleResize}
                onResizeStop={this.handleResizeStop}
                onChangeTab={this.handleChangeTab}
                editMode={editMode}  // 添加 editMode 属性
              />
            ))}
            {/* make the area below components droppable */}
            {editMode && gridComponent?.children?.length > 0 && (
              <DragDroppable
                component={gridComponent}
                depth={depth}
                parentComponent={null}
                index={gridComponent.children.length}
                orientation="column"
                onDrop={handleComponentDrop}
                className="empty-droptarget"
                editMode
              >
                {renderDraggableContentBottom}
              </DragDroppable>
            )}
            {isResizing &&
              Array(GRID_COLUMN_COUNT)
                .fill(null)
                .map((_, i) => (
                  <GridColumnGuide
                    key={`grid-column-${i}`}
                    className="grid-column-guide"
                    style={{
                      left: i * GRID_GUTTER_SIZE + i * columnWidth,
                      width: columnWidth,
                    }}
                  />
                ))}
          </GridContent>
        </div>
      </>
    );
  }
}

DashboardGrid.propTypes = propTypes;
DashboardGrid.defaultProps = defaultProps;

export default DashboardGrid;
