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
import { 
  GRID_GUTTER_SIZE, 
  GRID_COLUMN_COUNT,
  GRID_ROW_HEIGHT,
} from '../util/constants';
import { TAB_TYPE } from '../util/componentTypes';
import _ from 'lodash';

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
    
    @media (max-width: 768px) {
      .dashboard-grid {
        margin: ${theme.gridUnit}px;
        display: flex;
        flex-direction: column;
        width: 100%;
      }

      .dashboard-component-chart-holder {
        width: 100%;
        margin-bottom: ${theme.gridUnit * 2}px;
        background-color: ${theme.colors.grayscale.light5};
        
        .chart-container {
          width: 100%;
          height: ${window.innerWidth * 0.8}px !important;
          min-height: ${window.innerWidth * 0.8}px !important;
          
          .slice_container {
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;

            & > div {
              width: 100%;
              height: 100%;
            }

            canvas,
            .echarts-for-react {
              width: 100% !important;
              height: 100% !important;
            }
          }
        }
      }
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

// 1. 修改 GridContent 样式组件
const MOBILE_GRID_SETTINGS = {
  columnCount: 1,
  gutterSize: 4,  // 减小间距
  rowHeight: GRID_ROW_HEIGHT,  // 使用常量
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
      isMobile: false,
      isResizing: false,
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
    this.checkMobileMode();
    window.addEventListener('resize', this.handleResize);
  }

  componentWillUnmount() {
    window.removeEventListener('resize', this.handleResize);
  }

  checkMobileMode = () => {
    const isMobile = window.innerWidth <= 768;
    if (isMobile !== this.state.isMobile) {
      this.setState({ isMobile });
    }
  };

  handleResize = _.debounce(() => {
    this.checkMobileMode();
  }, 250);

  render() {
    const { isMobile, isResizing } = this.state;
    const {
      width,
      gridComponent,
      handleComponentDrop,
      depth,
      isComponentVisible,
      editMode,
      canEdit,
      setEditMode,
      dashboardId,
    } = this.props;
    
    // 移动端布局配置
    const gridSettings = isMobile ? MOBILE_GRID_SETTINGS : {
      columnCount: GRID_COLUMN_COUNT,
      gutterSize: GRID_GUTTER_SIZE,
      rowHeight: GRID_ROW_HEIGHT,
    };

    const columnWidth = Math.floor(
      (width - gridSettings.gutterSize * (gridSettings.columnCount - 1)) /
        gridSettings.columnCount,
    );

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
                availableColumnCount={gridSettings.columnCount}
                columnWidth={columnWidth}
                isComponentVisible={isComponentVisible}
                onResizeStart={this.handleResizeStart}
                onResize={this.handleResize}
                onResizeStop={this.handleResizeStop}
                onChangeTab={this.handleChangeTab}
                editMode={editMode}
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
