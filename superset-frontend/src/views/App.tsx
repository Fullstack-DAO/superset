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
import React, { Suspense, useEffect, useMemo } from 'react';
import { hot } from 'react-hot-loader/root';
import {
  BrowserRouter as Router,
  Switch,
  Route,
  useLocation,
} from 'react-router-dom';
import { bindActionCreators } from 'redux';
import { styled } from '@superset-ui/core';
import SplitPane from 'react-split-pane';
import { GlobalStyles } from 'src/GlobalStyles';
import ErrorBoundary from 'src/components/ErrorBoundary';
import Loading from 'src/components/Loading';
import Menu from 'src/features/home/Menu';
import getBootstrapData from 'src/utils/getBootstrapData';
import ToastContainer from 'src/components/MessageToasts/ToastContainer';
import setupApp from 'src/setup/setupApp';
import setupPlugins from 'src/setup/setupPlugins';
import { routes, isFrontendRoute } from 'src/views/routes';
import { Logger, LOG_ACTIONS_SPA_NAVIGATION } from 'src/logger/LogUtils';
import setupExtensions from 'src/setup/setupExtensions';
import { logEvent } from 'src/logger/actions';
import { store } from 'src/views/store';
import { RootContextProviders } from './RootContextProviders';
import { ScrollToTop } from './ScrollToTop';

setupApp();
setupPlugins();
setupExtensions();

const bootstrapData = getBootstrapData();

let lastLocationPathname: string;

const HIDE_MENU_PATHS = new Set(['/superset/app/dashboard']);
const MENU_WIDTH_STORAGE_KEY = 'superset.menu.width';
const DEFAULT_MENU_WIDTH = 220;
const MIN_MENU_WIDTH = 200;
const MAX_MENU_WIDTH = 800;

const boundActions = bindActionCreators({ logEvent }, store.dispatch);

const normalizePathname = (pathname: string) =>
  pathname.replace(/\/$/, '') || '/';

const shouldHideMenu = (pathname: string) =>
  HIDE_MENU_PATHS.has(normalizePathname(pathname));

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

const LocationPathnameLogger = () => {
  const location = useLocation();
  useEffect(() => {
    // This will log client side route changes for single page app user navigation
    boundActions.logEvent(LOG_ACTIONS_SPA_NAVIGATION, {
      path: location.pathname,
    });
    // reset performance logger timer start point to avoid soft navigation
    // cause dashboard perf measurement problem
    if (lastLocationPathname && lastLocationPathname !== location.pathname) {
      Logger.markTimeOrigin();
    }
    lastLocationPathname = location.pathname;
  }, [location.pathname]);
  return <></>;
};

const MenuWrapper = () => (
  <Menu
    data={bootstrapData.common.menu_data}
    isFrontendRoute={isFrontendRoute}
  />
);

const LayoutContainer = styled.div`
  display: flex;
  flex-direction: row;
  height: 100vh;
  overflow: hidden;
`;

const SplitPaneWrapper = styled.div`
  flex: 1;
  min-width: 0;
  min-height: 0;

  .SplitPane {
    position: relative !important;
    height: 100% !important;
  }

  .Pane {
    height: 100%;
    overflow: hidden;
  }

  .Resizer {
    background: ${({ theme }) => theme.colors.grayscale.light2};
    box-sizing: border-box;
    background-clip: padding-box;
    z-index: 1;
  }

  .Resizer.vertical {
    width: 8px;
    margin: 0 -4px;
    border-left: 3px solid transparent;
    border-right: 4px solid transparent;
    cursor: col-resize;
    transition: border-color 0.2s ease;
  }

  .Resizer.vertical:hover {
    border-left-color: ${({ theme }) => theme.colors.primary.light4};
    border-right-color: ${({ theme }) => theme.colors.primary.light4};
  }
`;

const MainContent = styled.div`
  flex: 1;
  height: 100%;
  overflow: auto;
  min-width: 0;
`;

const RoutesView = () => (
  <MainContent>
    <Switch>
      {routes.map(({ path, Component, props = {}, Fallback = Loading }) => (
        <Route path={path} key={path}>
          <Suspense fallback={<Fallback />}>
            <ErrorBoundary>
              <Component user={bootstrapData.user} {...props} />
            </ErrorBoundary>
          </Suspense>
        </Route>
      ))}
    </Switch>
  </MainContent>
);

const AppLayout = () => {
  const location = useLocation();
  const hideMenu = shouldHideMenu(location.pathname);
  const initialMenuWidth = useMemo(() => getInitialMenuWidth(), []);

  const handleMenuResizeFinished = (nextWidth: number) => {
    const normalizedWidth = Math.max(
      MIN_MENU_WIDTH,
      Math.min(MAX_MENU_WIDTH, Number(nextWidth) || DEFAULT_MENU_WIDTH),
    );

    window.localStorage.setItem(MENU_WIDTH_STORAGE_KEY, `${normalizedWidth}`);
  };

  return (
    <LayoutContainer>
      {hideMenu ? (
        <RoutesView />
      ) : (
        <SplitPaneWrapper>
          <SplitPane
            split="vertical"
            primary="first"
            minSize={MIN_MENU_WIDTH}
            maxSize={MAX_MENU_WIDTH}
            defaultSize={initialMenuWidth}
            onDragFinished={handleMenuResizeFinished}
            pane1Style={{ overflow: 'hidden' }}
            pane2Style={{ overflow: 'hidden' }}
          >
            <MenuWrapper />
            <RoutesView />
          </SplitPane>
        </SplitPaneWrapper>
      )}
    </LayoutContainer>
  );
};

const App = () => (
  <Router>
    <ScrollToTop />
    <LocationPathnameLogger />
    <RootContextProviders>
      <GlobalStyles />
      <AppLayout />
      <ToastContainer />
    </RootContextProviders>
  </Router>
);

export default hot(App);
