import React, { useEffect, useState } from 'react';
import { useSelector } from 'react-redux';
import { SupersetClient, styled } from '@superset-ui/core';
import { DashboardPage } from 'src/dashboard/containers/DashboardPage';
import { RootState } from 'src/dashboard/types';
import Loading from 'src/components/Loading';

const StyledContainer = styled.div`
  display: flex;
  flex-direction: column;
  height: 100vh;
`;

interface Dashboard {
  id: number;
  dashboard_title: string;
  url: string;
}

const AppDashboard = () => {
  const [dashboards, setDashboards] = useState<Dashboard[]>([]);
  const [selectedId, setSelectedId] = useState<string | undefined>(undefined);
  const [emptyStateText, setEmptyStateText] = useState('无更多数据');
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [isCheckingCharts, setIsCheckingCharts] = useState(false);
  const [hasCharts, setHasCharts] = useState(true);
  const urlParams = new URLSearchParams(window.location.search);
  const dsIdParam = urlParams.get('dsId') ?? undefined;
  const emailParam = urlParams.get('email')?.trim().toLowerCase();
  
  // @ts-ignore
  const user = useSelector<RootState, any>(state => state.user);
  const userId = user?.userId;
  const currentUserEmail = user?.email?.trim().toLowerCase();

  useEffect(() => {
    if (emailParam && currentUserEmail !== emailParam) {
      setIsLoggingIn(true);
      SupersetClient.get({ 
        endpoint: `/custom/login_by_email?email=${encodeURIComponent(emailParam)}` 
      })
        .then(({ json }) => {
          if (json.status === 'success') {
             window.location.reload();
          } else {
             console.error('Login failed:', json.message);
             setIsLoggingIn(false);
          }
        })
        .catch(err => {
          console.error('Login error:', err);
          setIsLoggingIn(false);
        });
      return;
    }

    if (!userId) {
      return;
    }

    if (dsIdParam) {
      setIsLoading(true);
      SupersetClient.get({
        endpoint: `/api/v1/dashboard/${encodeURIComponent(dsIdParam)}`,
      })
        .then(({ json }) => {
          if (json?.result?.id) {
            setSelectedId(dsIdParam);
            setDashboards([]);
            setEmptyStateText('无更多数据');
            return;
          }

          setSelectedId(undefined);
          setDashboards([]);
          setHasCharts(true);
          setEmptyStateText('无更多数据');
        })
        .catch(() => {
          setSelectedId(undefined);
          setDashboards([]);
          setHasCharts(true);
          setEmptyStateText('无更多数据');
        })
        .finally(() => {
          setIsLoading(false);
        });
      return;
    }

    setIsLoading(true);
    SupersetClient.get({
      endpoint: '/api/v1/dashboard/?q=(order_column:changed_on_delta_humanized,order_direction:desc,page:0,page_size:100)',
    }).then(({ json }) => {
      const { result } = json;
      setDashboards(result);
      if (result.length > 0) {
        setSelectedId(String(result[0].id));
        setEmptyStateText('无更多数据');
      } else {
        setSelectedId(undefined);
        setHasCharts(true);
        setEmptyStateText('无更多数据');
      }
    }).catch(error => {
      console.error('Error fetching dashboards:', error);
    }).finally(() => {
      setIsLoading(false);
    });
  }, [currentUserEmail, dsIdParam, emailParam, userId]);

  useEffect(() => {
    if (!userId || !selectedId) {
      return undefined;
    }

    let isMounted = true;
    setIsCheckingCharts(true);

    SupersetClient.get({
      endpoint: `/api/v1/dashboard/${encodeURIComponent(selectedId)}/charts`,
    })
      .then(({ json }) => {
        if (!isMounted) {
          return;
        }

        const charts = Array.isArray(json?.result) ? json.result : [];
        const dashboardHasCharts = charts.length > 0;

        setHasCharts(dashboardHasCharts);
        setEmptyStateText(dashboardHasCharts ? '无更多数据' : '此仪表盘无图表');
      })
      .catch(error => {
        if (!isMounted) {
          return;
        }

        console.error('Error fetching dashboard charts:', error);
        setHasCharts(true);
        setEmptyStateText('无更多数据');
      })
      .finally(() => {
        if (isMounted) {
          setIsCheckingCharts(false);
        }
      });

    return () => {
      isMounted = false;
    };
  }, [selectedId, userId]);

  if (isLoggingIn || isLoading || isCheckingCharts) {
    return <Loading />;
  }

  if (!userId) {
    return <div>请先登录</div>;
  }

  if ((!selectedId && dashboards.length === 0) || !hasCharts) {
    return (
      <StyledContainer>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <img style={{ width: '100%' }} src="/static/assets/images/app-empty-dashboard.png" alt="" />
          <p style={{ color: '#9E9E9E', fontSize: '18px', marginTop: '-60px' }}>{emptyStateText}</p>
        </div>
      </StyledContainer>
    );
  }

  return (
    <StyledContainer>
      {selectedId && (
        <div style={{ flex: 1, overflow: 'auto', position: 'relative' }}>
          <DashboardPage
            key={selectedId}
            idOrSlug={selectedId}
            isAppDashboard
          />
        </div>
      )}
    </StyledContainer>
  );
};

export default AppDashboard;
