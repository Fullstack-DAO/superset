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
/* eslint camelcase: 0 */
import React from 'react';
import { Dispatch } from 'redux';
import rison from 'rison';
import { connect } from 'react-redux';
import { withRouter, RouteComponentProps } from 'react-router-dom';
import { InfoTooltipWithTrigger } from '@superset-ui/chart-controls';
import {
  css,
  DatasourceType,
  isFeatureEnabled,
  FeatureFlag,
  isDefined,
  styled,
  SupersetClient,
  t,
} from '@superset-ui/core';
import { Input } from 'src/components/Input';
import { Form, FormItem } from 'src/components/Form';
import Alert from 'src/components/Alert';
import Modal from 'src/components/Modal';
import { Radio } from 'src/components/Radio';
import Button from 'src/components/Button';
import { AsyncSelect } from 'src/components';
import Loading from 'src/components/Loading';
import { setSaveChartModalVisibility } from 'src/explore/actions/saveModalActions';
import { SaveActionType } from 'src/explore/types';
import { UserWithPermissionsAndRoles } from 'src/types/bootstrapTypes';
import { Dashboard } from 'src/types/Dashboard';

// Session storage key for recent dashboard
const SK_DASHBOARD_ID = 'save_chart_recent_dashboard';

interface SaveModalProps extends RouteComponentProps {
  addDangerToast: (msg: string) => void;
  actions: Record<string, any>;
  form_data?: Record<string, any>;
  user: UserWithPermissionsAndRoles;
  alert?: string;
  sliceName?: string;
  slice?: Record<string, any>;
  datasource?: Record<string, any>;
  dashboardId: '' | number | null;
  isVisible: boolean;
  dispatch: Dispatch;
  chartPermissions?: {
    user_permissions?: string[];
    role_permissions?: string[];
  };
  persistedPermissions?: {
    canOverwrite: boolean;
    permissions: any;
  };
}
interface DashboardGetResponse {
  id: number;
  url: string;
  dashboard_title: string;
}

type SaveModalState = {
  newSliceName?: string;
  datasetName: string;
  action: SaveActionType;
  isLoading: boolean;
  saveStatus?: string | null;
  vizType?: string;
  dashboard?: { label: string; value: string | number };
};

export const StyledModal = styled(Modal)`
  .ant-modal-body {
    overflow: visible;
  }
  i {
    position: absolute;
    top: -${({ theme }) => theme.gridUnit * 5.25}px;
    left: ${({ theme }) => theme.gridUnit * 26.75}px;
  }
`;

class SaveModal extends React.Component<SaveModalProps, SaveModalState> {
  constructor(props: SaveModalProps) {
    super(props);
    this.state = {
      newSliceName: props.sliceName,
      datasetName: props.datasource?.name,
      action: 'overwrite',
      isLoading: false,
      vizType: props.form_data?.viz_type,
      dashboard: undefined
    };
    this.onDashboardChange = this.onDashboardChange.bind(this);
    this.onSliceNameChange = this.onSliceNameChange.bind(this);
    this.changeAction = this.changeAction.bind(this);
    this.saveOrOverwrite = this.saveOrOverwrite.bind(this);
    this.isNewDashboard = this.isNewDashboard.bind(this);
    this.onHide = this.onHide.bind(this);
  }

  // 权限检查：是否具有 can_edit 权限
  canOverwriteSlice = () => Boolean(this.props.persistedPermissions?.canOverwrite);

  isNewDashboard(): boolean {
    const { dashboard } = this.state;
    return typeof dashboard?.value === 'string';
  }

  handleDatasetNameChange = (e: React.FormEvent<HTMLInputElement>) => {
    // @ts-expect-error
    this.setState({ datasetName: e.target.value });
  };

  onSliceNameChange(event: React.ChangeEvent<HTMLInputElement>) {
    this.setState({ newSliceName: event.target.value });
  }

  onDashboardChange(dashboard: { label: string; value: string | number }) {
    this.setState({ dashboard });
  }

  changeAction = (action: SaveActionType) => {
    this.setState({ action });
  };

  onHide() {
    this.props.dispatch(setSaveChartModalVisibility(false));
  }

  handleRedirect = (windowLocationSearch: string, chart: any) => {
    const searchParams = new URLSearchParams(windowLocationSearch);
    searchParams.set('save_action', this.state.action);
    if (this.state.action !== 'overwrite') {
      searchParams.delete('form_data_key');
    }

    searchParams.set('slice_id', chart.id.toString());
    return searchParams;
  };

  saveOrOverwrite = async (gotodash: boolean) => {
    this.setState({ isLoading: true });
    try {
      if (this.props.datasource?.type === DatasourceType.Query) {
        const { schema, sql, database } = this.props.datasource;
        const { templateParams } = this.props.datasource;

        await this.props.actions.saveDataset({
          schema,
          sql,
          database,
          templateParams,
          datasourceName: this.state.datasetName,
        });
      }

      // 获取图表对应的 dashboards
      let sliceDashboards: number[] = [];
      if (this.props.slice && this.state.action === 'overwrite') {
        sliceDashboards = await this.props.actions.getSliceDashboards(
          this.props.slice,
        );
      }

      const formData = this.props.form_data || {};
      delete formData.url_params;

      let dashboard: DashboardGetResponse | null = null;
      if (this.state.dashboard) {
        let validId = this.state.dashboard.value;
        if (this.isNewDashboard()) {
          const response = await this.props.actions.createDashboard(
            this.state.dashboard.label,
          );
          validId = response.id;
        }

        try {
          dashboard = await this.loadDashboard(validId as number);
        } catch (error) {
          this.props.actions.saveSliceFailed();
          return;
        }

        if (isDefined(dashboard) && isDefined(dashboard?.id)) {
          sliceDashboards = sliceDashboards.includes(dashboard.id)
            ? sliceDashboards
            : [...sliceDashboards, dashboard.id];
          formData.dashboards = sliceDashboards;
        }
      }

      // 更新表单数据
      this.props.actions.setFormData({ ...formData });

      // 更新或创建切片
      let value: { id: number };
      if (this.state.action === 'overwrite') {
        value = await this.props.actions.updateSlice(
          this.props.slice,
          this.state.newSliceName,
          sliceDashboards,
          dashboard
            ? {
              title: dashboard.dashboard_title,
              new: this.isNewDashboard(),
            }
            : null,
        );
      } else {
        value = await this.props.actions.createSlice(
          this.state.newSliceName,
          sliceDashboards,
          dashboard
            ? {
              title: dashboard.dashboard_title,
              new: this.isNewDashboard(),
            }
            : null,
        );
      }

      // 保存或跳转至新创建的 dashboard 页面
      try {
        if (dashboard) {
          sessionStorage.setItem(SK_DASHBOARD_ID, `${dashboard.id}`);
        } else {
          sessionStorage.removeItem(SK_DASHBOARD_ID);
        }
      } catch (error) {
        // continue regardless of error
      }

      // Go to new dashboard URL
      if (gotodash && dashboard) {
        this.props.history.push(dashboard.url);
        return;
      }

      const searchParams = this.handleRedirect(window.location.search, value);
      this.props.history.replace(`/explore/?${searchParams.toString()}`);

    } catch (error) {
      if (error?.response?.status === 403) {
        this.props.addDangerToast(t('你没有编辑该图表的权限！'));
        this.setState({ action: 'saveas' });
      }
    } finally {
      this.setState({ isLoading: false });
    }
  };

  loadDashboard = async (id: number): Promise<Dashboard> => {
    const response = await SupersetClient.get({
      endpoint: `/api/v1/dashboard/${id}`,
    });
    return response.json.result;
  };

  loadDashboards = async (search: string, page: number, pageSize: number) => {
    const queryParams = rison.encode({
      columns: ['id', 'dashboard_title'],
      filters: [
        {
          col: 'dashboard_title',
          opr: 'ct',
          value: search,
        },
        {
          col: 'owners',
          opr: 'rel_m_m',
          value: this.props.user.userId,
        },
      ],
      page,
      page_size: pageSize,
      order_column: 'dashboard_title',
    });

    const { json } = await SupersetClient.get({
      endpoint: `/api/v1/dashboard/?q=${queryParams}`,
    });
    const { result, count } = json;
    return {
      data: result.map(
        (dashboard: { id: number; dashboard_title: string }) => ({
          value: dashboard.id,
          label: dashboard.dashboard_title,
        }),
      ),
      totalCount: count,
    };
  };

  renderSaveChartModal = () => (
    <Form data-test="save-modal-body" layout="vertical">
      <FormItem data-test="radio-group">
        <Radio.Group
          value={this.state.action}
          onChange={e => this.changeAction(e.target.value)}
        >
          <Radio
            value="overwrite"
            data-test="save-overwrite-radio"
          >
            {t('Save (Overwrite)')}
          </Radio>
          <Radio
            value="saveas"
            data-test="saveas-radio"
          >
            {t('Save as...')}
          </Radio>
        </Radio.Group>
      </FormItem>
      <hr />
      <FormItem label={t('Chart name')} required>
        <Input
          name="new_slice_name"
          type="text"
          placeholder="Name"
          value={this.state.newSliceName}
          onChange={this.onSliceNameChange}
          data-test="new-chart-name"
        />
      </FormItem>
      {this.props.datasource?.type === 'query' && (
        <FormItem label={t('Dataset Name')} required>
          <InfoTooltipWithTrigger
            tooltip={t('A reusable dataset will be saved with your chart.')}
            placement="right"
          />
          <Input
            name="dataset_name"
            type="text"
            placeholder="Dataset Name"
            value={this.state.datasetName}
            onChange={this.handleDatasetNameChange}
            data-test="new-dataset-name"
          />
        </FormItem>
      )}
      {!(
        isFeatureEnabled(FeatureFlag.DASHBOARD_NATIVE_FILTERS) &&
        this.state.vizType === 'filter_box'
      ) && (
        <FormItem
          label={t('Add to dashboard')}
          data-test="save-chart-modal-select-dashboard-form"
        >
          <AsyncSelect
            allowClear
            allowNewOptions
            ariaLabel={t('Select a dashboard')}
            options={this.loadDashboards}
            onChange={this.onDashboardChange}
            value={this.state.dashboard}
            placeholder={
              <div>
                <b>{t('Select')}</b>
                {t(' a dashboard OR ')}
                <b>{t('create')}</b>
                {t(' a new one')}
              </div>
            }
          />
        </FormItem>
      )}
      {this.info() && <Alert type="info" message={this.info()} closable={false} />}
      {this.props.alert && (
        <Alert
          css={{ marginTop: this.info() ? 16 : undefined }}
          type="warning"
          message={this.props.alert}
          closable={false}
        />
      )}
    </Form>
  );

  info = () => {
    const isNewDashboard = this.isNewDashboard();
    let chartWillBeCreated = false;
    if (
      this.props.slice &&
      (this.state.action !== 'overwrite' || !this.canOverwriteSlice())
    ) {
      chartWillBeCreated = true;
    }
    if (chartWillBeCreated && isNewDashboard) {
      return t('A new chart and dashboard will be created.');
    }
    if (chartWillBeCreated) {
      return t('A new chart will be created.');
    }
    if (isNewDashboard) {
      return t('A new dashboard will be created.');
    }
    return null;
  };

  renderFooter = () => (
    <div data-test="save-modal-footer">
      <Button id="btn_cancel" buttonSize="small" onClick={this.onHide}>
        {t('Cancel')}
      </Button>
      <Button
        id="btn_modal_save_goto_dash"
        buttonSize="small"
        disabled={
          !this.state.newSliceName ||
          !this.state.dashboard ||
          (this.props.datasource?.type !== DatasourceType.Table &&
            !this.state.datasetName) ||
          (isFeatureEnabled(FeatureFlag.DASHBOARD_NATIVE_FILTERS) &&
            this.state.vizType === 'filter_box')
        }
        onClick={() => this.saveOrOverwrite(true)}
      >
        {t('Save & go to dashboard')}
      </Button>
      <Button
        id="btn_modal_save"
        buttonSize="small"
        buttonStyle="primary"
        onClick={() => this.saveOrOverwrite(false)}
        disabled={
          this.state.isLoading ||
          !this.state.newSliceName ||
          (this.props.datasource?.type !== DatasourceType.Table &&
            !this.state.datasetName)
        }
        data-test="btn-modal-save"
      >
        {t('Save')}
      </Button>
    </div>
  );

  render() {
    const { isLoading } = this.state;
    return (
      <StyledModal
        show={this.props.isVisible}
        onHide={this.onHide}
        title={t('Save chart')}
        footer={this.renderFooter()}
      >
        {isLoading ? (
          <div
            css={css`
              display: flex;
              justify-content: center;
            `}
          >
            <Loading position="normal" />
          </div>
        ) : (
          this.renderSaveChartModal()
        )}
      </StyledModal>
    );
  }
}

interface StateProps {
  datasource: any;
  slice: any;
  user: UserWithPermissionsAndRoles;
  dashboards: any;
  alert: any;
  isVisible: boolean;
  persistedPermissions: any;
}

function mapStateToProps({
  explore,
  saveModal,
  user,
}: Record<string, any>): StateProps {
  return {
    datasource: explore.datasource,
    slice: explore.slice,
    user,
    dashboards: saveModal.dashboards,
    alert: saveModal.saveModalAlert,
    isVisible: saveModal.isVisible,
    persistedPermissions: saveModal.chartPermissions,
  };
}

export default withRouter(connect(mapStateToProps)(SaveModal));

// User for testing purposes need to revisit once we convert this to functional component
export { SaveModal as PureSaveModal };
