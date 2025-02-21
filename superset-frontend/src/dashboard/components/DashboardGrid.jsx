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
import _ from 'lodash';
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

const GRID_SETTINGS = {
  default: {
    columnCount: GRID_COLUMN_COUNT,
    gutterSize: GRID_GUTTER_SIZE,
    rowHeight: GRID_ROW_HEIGHT,
  },
  mobile: {
    columnCount: 1,
    gutterSize: 8,
    rowHeight: 350,
    minWidth: 320,
  },
};

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

const GridContent = styled.div`
  position: relative;
  width: 100%;
  height: 100%;

  @media (max-width: 768px) {
    .dashboard-grid {
      display: block !important;
      width: 100% !important;
      padding: ${({ theme }) => theme.gridUnit * 2}px;
      margin: 0;

      // 添加顶部操作按钮的样式
      .dashboard-header-actions {
        display: flex;
        align-items: center;
        justify-content: flex-end;
        gap: ${({ theme }) => theme.gridUnit * 2}px;
        margin-bottom: ${({ theme }) => theme.gridUnit * 2}px;

        button {
          margin: 0;
        }
      }
      .dashboard-component-chart-holder {
        position: relative !important;
        width: 100% !important;
        margin-bottom: ${({ theme }) => theme.gridUnit * 4}px;
        padding: ${({ theme }) => theme.gridUnit * 2}px;
        background-color: ${({ theme }) => theme.colors.grayscale.light5};
        border-radius: ${({ theme }) => theme.gridUnit}px;
        box-sizing: border-box;

        .chart-container {
          position: relative !important;
          width: 100% !important;
          height: 350px !important;
          margin: 0;
          padding: 0;
          box-sizing: border-box;

          .slice_container {
            position: relative !important;
            width: 100% !important;
            height: 100% !important;
            display: flex;
            align-items: center;
            justify-content: center;
            box-sizing: border-box;

            & > div {
              width: 100% !important;
              height: 100% !important;
              position: relative !important;
            }

            svg,
            canvas {
              width: 100% !important;
              height: 100% !important;
              position: relative !important;
            }

            &.big_number {
              display: flex;
              align-items: center;
              justify-content: center;
              height: 200px !important;
              span {
                font-size: 48px;
                line-height: 1.2;
              }
            }
          }
        }
      }
    }

    .empty-droptarget {
      display: none;
    }
  }
`;

class DashboardGrid extends React.PureComponent {
  constructor(props) {
    super(props);
    this.state = {
      isMobile: false,
      isResizing: false,
      mounted: false,
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
    setTimeout(() => {
      this.setState({ mounted: true });
    }, 100);
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
    this.setState({ mounted: false }, () => {
      setTimeout(() => {
        this.setState({ mounted: true });
      }, 100);
    });
  }, 250);

  render() {
    const { isMobile, isResizing, mounted } = this.state;
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

    const gridSettings = isMobile
      ? GRID_SETTINGS.mobile
      : GRID_SETTINGS.default;

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
          <GridContent
            className="grid-content"
            data-test="grid-content"
            style={{ visibility: mounted ? 'visible' : 'hidden' }}
          >
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
