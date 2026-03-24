import React, { useEffect, useState } from 'react';
import { useSelector } from 'react-redux';
import { Select } from 'antd';
import { SupersetClient, styled, t } from '@superset-ui/core';
import { DashboardPage } from 'src/dashboard/containers/DashboardPage';
import { RootState } from 'src/dashboard/types';
import Loading from 'src/components/Loading';

const StyledContainer = styled.div<{ showBackground?: boolean }>`
  display: flex;
  flex-direction: column;
  height: 100vh;
  background: #F6FBF1 ${({ showBackground }) =>
    showBackground
      ? "url('/static/assets/images/app-bg-2.png') no-repeat center top"
      : ''};
  background-size: contain;
  
  .dashboard-select-container {
    padding: 120px 5px 16px;
    background: transparent;
    display: flex;
    align-items: center;
  }
`;

const StyledSelect = styled(Select)`
  width: fit-content;
  max-width: calc(100vw - 10px);
  min-width: 0;

  .ant-select-selector,
  &.ant-select-single:not(.ant-select-customize-input) .ant-select-selector {
    width: auto !important;
    max-width: calc(100vw - 10px);
  }
  
  .ant-select-selector {
    background-color: transparent !important;
    box-shadow: none !important;
  }

  .ant-select-selection-item {
    font-size: 24px !important;
    color: #fff !important;
    font-weight: 500;
  }

  .ant-select-arrow {
    color: #fff !important;
  }

  .ant-select-selection-placeholder {
    font-size: 24px;
    color: rgba(255, 255, 255, 0.7);
  }
`;

interface Dashboard {
  id: number;
  dashboard_title: string;
  url: string;
}

const AppDashboard = () => {
  const [dashboards, setDashboards] = useState<Dashboard[]>([]);
  const [selectedId, setSelectedId] = useState<string | undefined>(undefined);
  const [isLoggingIn, setIsLoggingIn] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  
  // @ts-ignore
  const user = useSelector<RootState, any>(state => state.user);
  const userId = user?.userId;

  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const emailParam = urlParams.get('email');

    if (!userId && emailParam) {
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

    setIsLoading(true);
    SupersetClient.get({
      endpoint: '/api/v1/dashboard/?q=(order_column:changed_on_delta_humanized,order_direction:desc,page:0,page_size:100)',
    }).then(({ json }) => {
      const { result } = json;
      setDashboards(result);
      if (result.length > 0) {
        setSelectedId(String(result[0].id));
      }
    }).catch(error => {
      console.error('Error fetching dashboards:', error);
    }).finally(() => {
      setIsLoading(false);
    });
  }, [userId]);

  const handleChange = (value: string) => {
    setSelectedId(value);
  };

  if (isLoggingIn || isLoading) {
    return <Loading />;
  }

  if (!userId) {
    return <div>请先登录</div>;
  }

  if (dashboards.length === 0) {
    return (
      <StyledContainer showBackground={false}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
          <img style={{ width: '100%' }} src="/static/assets/images/app-empty-dashboard.png" alt="" />
          <p style={{ color: '#9E9E9E', fontSize: '18px', marginTop: '-60px' }}>无更多数据</p>
        </div>
      </StyledContainer>
    );
  }

  const options = dashboards.map(d => ({
    label: d.dashboard_title,
    value: String(d.id),
  }));

  return (
    <StyledContainer showBackground>
      <div className="dashboard-select-container">
        <StyledSelect
          aria-label={t('Select Dashboard')}
          options={options}
          value={selectedId}
          onChange={handleChange}
          placeholder={t('Select a dashboard')}
          bordered={false}
          dropdownMatchSelectWidth={false}
          dropdownStyle={{ width: 230 }}
        />
      </div>
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
