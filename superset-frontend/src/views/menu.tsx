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

// Menu App. Used in views that do not already include the Menu component in the layout.
// eg, backend rendered views
import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Provider } from 'react-redux';
import ReactDOM from 'react-dom';
import { Route, BrowserRouter } from 'react-router-dom';
import { CacheProvider } from '@emotion/react';
import { QueryParamProvider } from 'use-query-params';
import createCache from '@emotion/cache';
import { styled, ThemeProvider } from '@superset-ui/core';
import Menu from 'src/features/home/Menu';
import { theme } from 'src/preamble';
import getBootstrapData from 'src/utils/getBootstrapData';
import { setupStore } from './store';

// Disable connecting to redux debugger so that the React app injected
// Below the menu like SqlLab or Explore can connect its redux store to the debugger
const store = setupStore({ disableDebugger: true });
const bootstrapData = getBootstrapData();
const menu = { ...bootstrapData.common.menu_data };
const MENU_WIDTH_STORAGE_KEY = 'superset.menu.width';
const MENU_COLLAPSED_STORAGE_KEY = 'superset.menu.collapsed';
const DEFAULT_MENU_WIDTH = 220;
const MIN_MENU_WIDTH = 200;
const MAX_MENU_WIDTH = 800;
const COLLAPSED_MENU_WIDTH = 72;

const emotionCache = createCache({
  key: 'menu',
});

const getInitialMenuWidth = () => {
  const savedWidth = Number(
    window.localStorage.getItem(MENU_WIDTH_STORAGE_KEY),
  );

  if (
    Number.isFinite(savedWidth) &&
    savedWidth >= MIN_MENU_WIDTH &&
    savedWidth <= MAX_MENU_WIDTH
  ) {
    return savedWidth;
  }

  return DEFAULT_MENU_WIDTH;
};

const getInitialMenuCollapsed = () =>
  window.localStorage.getItem(MENU_COLLAPSED_STORAGE_KEY) === 'true';

const MenuShell = styled.div<{ $collapsed?: boolean }>`
  position: relative;
  width: 100%;
  height: 100%;
  min-width: ${({ $collapsed }) =>
    $collapsed ? `${COLLAPSED_MENU_WIDTH}px` : `${MIN_MENU_WIDTH}px`};
  max-width: ${({ $collapsed }) =>
    $collapsed ? `${COLLAPSED_MENU_WIDTH}px` : `${MAX_MENU_WIDTH}px`};
  overflow: visible;
  will-change: width;
`;

const MenuResizeHandle = styled.div`
  position: absolute;
  top: 0;
  right: -7px;
  width: 8px;
  height: 100%;
  cursor: col-resize;
  z-index: 2;

  &::before {
    content: '';
    position: absolute;
    inset: 0;
    border-left: 1px solid ${({ theme }) => theme.colors.grayscale.light2};
    border-right: 1px solid transparent;
    transition: border-color 0.2s ease;
  }

  &:hover::before {
    border-left-color: ${({ theme }) => theme.colors.primary.light4};
  }
`;

const StandaloneMenuLayout = () => {
  const shellRef = useRef<HTMLDivElement | null>(null);
  const frameRef = useRef<number | null>(null);
  const startXRef = useRef(0);
  const startWidthRef = useRef(DEFAULT_MENU_WIDTH);
  const initialWidth = useMemo(() => getInitialMenuWidth(), []);
  const [menuWidth, setMenuWidth] = useState(initialWidth);
  const [isCollapsed, setIsCollapsed] = useState(getInitialMenuCollapsed);

  useEffect(() => {
    if (shellRef.current) {
      shellRef.current.style.width = isCollapsed
        ? `${COLLAPSED_MENU_WIDTH}px`
        : `${menuWidth}px`;
    }
  }, [isCollapsed, menuWidth]);

  useEffect(
    () => () => {
      if (frameRef.current) {
        window.cancelAnimationFrame(frameRef.current);
      }
    },
    [],
  );

  const setWidth = (nextWidth: number) => {
    const normalizedWidth = Math.max(
      MIN_MENU_WIDTH,
      Math.min(MAX_MENU_WIDTH, nextWidth),
    );

    setMenuWidth(normalizedWidth);

    if (frameRef.current) {
      window.cancelAnimationFrame(frameRef.current);
    }

    frameRef.current = window.requestAnimationFrame(() => {
      if (shellRef.current) {
        shellRef.current.style.width = `${normalizedWidth}px`;
      }
    });

    return normalizedWidth;
  };

  const handlePointerDown = (event: React.PointerEvent<HTMLDivElement>) => {
    if (isCollapsed) {
      return;
    }

    const shell = shellRef.current;

    if (!shell) {
      return;
    }

    event.preventDefault();

    startXRef.current = event.clientX;
    startWidthRef.current = shell.getBoundingClientRect().width;

    const handlePointerMove = (moveEvent: PointerEvent) => {
      const delta = moveEvent.clientX - startXRef.current;
      setWidth(startWidthRef.current + delta);
    };

    const handlePointerUp = (upEvent: PointerEvent) => {
      const delta = upEvent.clientX - startXRef.current;
      const normalizedWidth = setWidth(startWidthRef.current + delta);

      window.localStorage.setItem(MENU_WIDTH_STORAGE_KEY, `${normalizedWidth}`);
      window.removeEventListener('pointermove', handlePointerMove);
      window.removeEventListener('pointerup', handlePointerUp);
    };

    window.addEventListener('pointermove', handlePointerMove);
    window.addEventListener('pointerup', handlePointerUp, { once: true });
  };

  const toggleMenuCollapse = () => {
    setIsCollapsed(current => {
      const next = !current;
      window.localStorage.setItem(MENU_COLLAPSED_STORAGE_KEY, `${next}`);
      return next;
    });
  };

  return (
    <MenuShell ref={shellRef} $collapsed={isCollapsed}>
      <Menu
        data={menu}
        isCollapsed={isCollapsed}
        onToggleCollapse={toggleMenuCollapse}
      />
      {!isCollapsed && <MenuResizeHandle onPointerDown={handlePointerDown} />}
    </MenuShell>
  );
};

const app = (
  // @ts-ignore: emotion types defs are incompatible between core and cache
  <CacheProvider value={emotionCache}>
    <ThemeProvider theme={theme}>
      <Provider store={store}>
        <BrowserRouter>
          <QueryParamProvider
            ReactRouterRoute={Route}
            stringifyOptions={{ encode: false }}
          >
            <StandaloneMenuLayout />
          </QueryParamProvider>
        </BrowserRouter>
      </Provider>
    </ThemeProvider>
  </CacheProvider>
);

ReactDOM.render(app, document.getElementById('app-menu'));
