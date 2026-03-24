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
import React, { useState, useEffect } from 'react';
import { styled, css, useTheme, SupersetTheme } from '@superset-ui/core';
import { debounce } from 'lodash';
import { Global } from '@emotion/react';
import { getUrlParam } from 'src/utils/urlUtils';
import { Grid } from 'src/components';
import { MainNav as DropdownMenu, MenuMode } from 'src/components/Menu';
import { Tooltip } from 'src/components/Tooltip';
import { NavLink, useLocation } from 'react-router-dom';
import { GenericLink } from 'src/components/GenericLink/GenericLink';
import { useUiConfig } from 'src/components/UiConfigContext';
import { URL_PARAMS } from 'src/constants';
import {
  MenuObjectChildProps,
  MenuObjectProps,
  MenuData,
} from 'src/types/bootstrapTypes';
import getBootstrapData from 'src/utils/getBootstrapData';
import {
  CloseOutlined,
  MenuOutlined,
  DashboardOutlined,
  BarChartOutlined,
  DatabaseOutlined,
  RobotOutlined,
  PartitionOutlined,
  ReadOutlined,
  ConsoleSqlOutlined,
  FileOutlined,
  FolderOutlined,
} from '@ant-design/icons';
import { Button } from 'antd';
import RightMenu from './RightMenu';

const bootstrapData = getBootstrapData();

const iconMap: Record<string, React.ReactNode> = {
  'Dashboards': <DashboardOutlined />,
  'Charts': <BarChartOutlined />,
  'Datasets': <DatabaseOutlined />,
  'SQL Lab': <ConsoleSqlOutlined />,
  'SQL': <ConsoleSqlOutlined />,
  'Copilot': <RobotOutlined />,
  'Workflow': <PartitionOutlined />,
  '文档': <ReadOutlined />,
};

interface MenuProps {
  data: MenuData;
  isFrontendRoute?: (path?: string) => boolean;
}

const StyledHeader = styled.header`
  ${({ theme }) => `
      background-color: ${theme.colors.grayscale.light5};
      margin-bottom: 2px;
      z-index: 1000;
      box-shadow: 2px 0 8px 0 rgba(0, 0, 0, 0.05);
      width: 220px;
      flex-shrink: 0;
      height: 100vh;
      overflow-y: auto;

      .navbar-brand-container {
        display: flex;
        align-items: center;
        justify-content: center;
      }

      .caret {
        display: none;
      }
      .navbar-brand {
        display: flex;
        flex-direction: column;
        justify-content: center;
        /* must be exactly the height of the Antd navbar */
        min-height: 60px;
        padding: ${theme.gridUnit}px
          ${theme.gridUnit * 2}px
          ${theme.gridUnit}px
          ${theme.gridUnit * 2}px;
        max-width: ${theme.gridUnit * theme.brandIconMaxWidth}px;
        img {
          height: 100%;
          object-fit: contain;
        }
      }
      .navbar-brand-text {
        border-left: 1px solid ${theme.colors.grayscale.light2};
        border-right: 1px solid ${theme.colors.grayscale.light2};
        height: 100%;
        color: ${theme.colors.grayscale.dark1};
        padding-left: ${theme.gridUnit * 4}px;
        padding-right: ${theme.gridUnit * 4}px;
        margin-right: ${theme.gridUnit * 6}px;
        font-size: ${theme.gridUnit * 4}px;
        float: left;
        display: flex;
        flex-direction: column;
        justify-content: center;

        span {
          max-width: ${theme.gridUnit * 58}px;
          white-space: nowrap;
          overflow: hidden;
          text-overflow: ellipsis;
        }
        @media (max-width: 1127px) {
          display: none;
        }
      }

      @media (max-width: 767px) {
        .navbar-brand {
          float: none;
        }
      }

      .ant-menu-submenu-selected,
      .ant-menu-submenu:has(.ant-menu-item-selected),
      .ant-menu-submenu:has(.is-active) {
        > .ant-menu-submenu-title {
          color: ${theme.colors.primary.base} !important;
          .anticon {
            color: ${theme.colors.primary.base} !important;
          }
        }
      }

      .ant-menu-item-selected,
      .ant-menu-item:has(.is-active) {
        background-color: #E7F6EC !important;
        color: ${theme.colors.primary.base} !important;
        
        .anticon {
          color: ${theme.colors.primary.base} !important;
        }
        
        a {
          color: ${theme.colors.primary.base} !important;
        }

        &::after {
          content: '';
          position: absolute;
          top: 0;
          right: 0;
          bottom: 0;
          border-right: 3px solid ${theme.colors.primary.base} !important;
          transform: scaleY(1) !important;
          opacity: 1 !important;
        }

        &:hover {
          background-color: #E7F6EC !important;
          color: ${theme.colors.primary.base} !important;
          
          .anticon {
            color: ${theme.colors.primary.base} !important;
          }
          
          a {
            color: ${theme.colors.primary.base} !important;
          }
        }
      }

      .ant-menu-item:not(.ant-menu-item-selected):not(:has(.is-active)) {
        &:hover {
          background-color: ${theme.colors.primary.light5};
          color: ${theme.colors.primary.base};

          .anticon {
            color: ${theme.colors.primary.base};
          }

          a {
            color: ${theme.colors.primary.base};
            text-decoration: none;
          }
        }
      }
  `}
`;

const globalStyles = (theme: SupersetTheme) => css``;
const { SubMenu } = DropdownMenu;

const { useBreakpoint } = Grid;

export function Menu({
  data: {
    menu,
    brand,
    navbar_right: navbarRight,
    settings,
    environment_tag: environmentTag,
  },
  isFrontendRoute = () => false,
}: MenuProps) {
  const [showMenu, setMenu] = useState<MenuMode>('vertical');
  const screens = useBreakpoint();
  const uiConfig = useUiConfig();
  const theme = useTheme();
  const [menuOpen, setMenuOpen] = useState(false);

  useEffect(() => {
    function handleResize() {
      if (window.innerWidth <= 767) {
        setMenu('inline');
      } else setMenu('inline');
    }
    handleResize();
    const windowResize = debounce(() => handleResize(), 10);
    window.addEventListener('resize', windowResize);
    return () => window.removeEventListener('resize', windowResize);
  }, []);

  enum paths {
    EXPLORE = '/explore',
    DASHBOARD = '/dashboard',
    CHART = '/chart',
    DATASETS = '/tablemodelview',
  }

  const defaultTabSelection: string[] = [];
  const [activeTabs, setActiveTabs] = useState(defaultTabSelection);
  const location = useLocation();
  useEffect(() => {
    const path = location.pathname;
    switch (true) {
      case path.startsWith(paths.DASHBOARD):
        setActiveTabs(['Dashboards']);
        break;
      case path.startsWith(paths.CHART) || path.startsWith(paths.EXPLORE):
        setActiveTabs(['Charts']);
        break;
      case path.startsWith(paths.DATASETS):
        setActiveTabs(['Datasets']);
        break;
      default:
        setActiveTabs(defaultTabSelection);
    }
  }, [location.pathname]);

  const standalone = getUrlParam(URL_PARAMS.standalone);
  if (standalone || uiConfig.hideNav) return <></>;

  const renderSubMenu = ({
    name,
    label,
    childs,
    url,
    index,
    isFrontendRoute,
  }: MenuObjectProps) => {
    const icon = iconMap[name || ''] || <FileOutlined />;

    if (url && isFrontendRoute) {
      return (
        <DropdownMenu.Item key={label} role="presentation" icon={icon}>
          <NavLink role="button" to={url} activeClassName="is-active">
            {label}
          </NavLink>
        </DropdownMenu.Item>
      );
    }
    if (url) {
      return (
        <DropdownMenu.Item key={label} icon={icon}>
          <a href={url}>{label}</a>
        </DropdownMenu.Item>
      );
    }

    const renderChild = (child: MenuObjectChildProps | string, idx: number) => {
      if (typeof child === 'string') {
        if (child === '-' && label !== 'Data') {
          return <DropdownMenu.Divider key={`divider-${idx}`} />;
        }
        return null;
      }

      const childObj = child as MenuObjectProps;
      const hasChildren = childObj.childs && childObj.childs.length > 0;

      if (hasChildren) {
        return (
          <SubMenu
            key={child.label}
            title={child.label}
            icon={<FolderOutlined />}
          >
            {childObj.childs?.map((grandChild, grandIdx) =>
              renderChild(grandChild, grandIdx),
            )}
          </SubMenu>
        );
      }

      return (
        <DropdownMenu.Item key={child.label} icon={<FileOutlined />}>
          {child.isFrontendRoute ? (
            <NavLink to={child.url || ''} exact activeClassName="is-active">
              {child.label}
            </NavLink>
          ) : (
            <a href={child.url}>{child.label}</a>
          )}
        </DropdownMenu.Item>
      );
    };

    return (
      <SubMenu key={index} title={label} icon={icon}>
        {childs?.map((child, index1) => renderChild(child, index1))}
      </SubMenu>
    );
  };

  return (
    <StyledHeader className="top" id="main-menu" role="navigation">
      <Global styles={globalStyles(theme)} />
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          height: '100%',
        }}
      >
        <div className="navbar-brand-container">
          <Tooltip
            id="brand-tooltip"
            placement="bottomLeft"
            title={brand.tooltip}
            arrowPointAtCenter
          >
            {isFrontendRoute(window.location.pathname) ? (
              <GenericLink className="navbar-brand" to={brand.path}>
                <img src={brand.icon} alt={brand.alt} />
              </GenericLink>
            ) : (
              <a className="navbar-brand" href={brand.path}>
                <img src={brand.icon} alt={brand.alt} />
              </a>
            )}
          </Tooltip>
        </div>

        {!screens.md && (
          <div style={{ padding: '0 16px 16px' }}>
            <Button
              size="large"
              color="black"
              type="link"
              onClick={() => {
                setMenuOpen(!menuOpen);
              }}
              icon={menuOpen ? <CloseOutlined /> : <MenuOutlined />}
            />
          </div>
        )}

        <DropdownMenu
          mode={showMenu}
          data-test="navbar-top"
          className="main-nav"
          style={{
            maxHeight: !screens.md && !menuOpen ? '0' : 'none',
            flex: 1,
            overflowY: 'auto',
            borderRight: 'none',
          }}
          selectedKeys={activeTabs}
        >
          {menu.map((item, index) => {
            const props = {
              index,
              ...item,
              isFrontendRoute: isFrontendRoute(item.url),
              childs: item.childs?.map(c => {
                if (typeof c === 'string') {
                  return c;
                }

                return {
                  ...c,
                  isFrontendRoute: isFrontendRoute(c.url),
                };
              }),
            };

            return renderSubMenu(props);
          })}
          <DropdownMenu.Item role="presentation">
            <a
              role="button"
              href={bootstrapData.common.docs_url}
              rel="noreferrer noopener"
              target="_blank"
            >
              <span>
                <ReadOutlined />
              </span>
              文档
            </a>
          </DropdownMenu.Item>
        </DropdownMenu>

        <div style={{ marginTop: 'auto' }}>
          <RightMenu
            align="flex-start"
            settings={settings}
            navbarRight={navbarRight}
            isFrontendRoute={isFrontendRoute}
            environmentTag={environmentTag}
          />
        </div>
      </div>
    </StyledHeader>
  );
}

// transform the menu data to reorganize components
export default function MenuWrapper({ data, ...rest }: MenuProps) {
  const newMenuData = {
    ...data,
  };
  // Menu items that should go into settings dropdown
  const settingsMenus = {
    Data: true,
    Security: true,
    Manage: true,
  };

  // Cycle through menu.menu to build out cleanedMenu and settings
  const cleanedMenu: MenuObjectProps[] = [];
  const settings: MenuObjectProps[] = [];
  newMenuData.menu.forEach((item: any) => {
    if (!item || item.name === 'Home') {
      return;
    }

    const children: (MenuObjectProps | string)[] = [];
    const newItem = {
      ...item,
    };

    // Filter childs
    if (item.childs) {
      item.childs.forEach((child: MenuObjectChildProps | string) => {
        if (typeof child === 'string') {
          children.push(child);
        } else if ((child as MenuObjectChildProps).label) {
          children.push(child);
        }
      });

      newItem.childs = children;
    }

    if (!settingsMenus.hasOwnProperty(item.name)) {
      cleanedMenu.push(newItem);
    } else {
      settings.push(newItem);
    }
  });

  newMenuData.menu = cleanedMenu;
  newMenuData.settings = settings;

  return <Menu data={newMenuData} {...rest} />;
}
