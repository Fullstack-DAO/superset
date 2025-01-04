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
import React, { useMemo, useState, useCallback, useEffect } from 'react';
import Modal from 'src/components/Modal';
import { Input, TextArea } from 'src/components/Input';
import Button from 'src/components/Button';
import { AsyncSelect, Row, Col, AntdForm } from 'src/components';
import { SelectValue } from 'antd/lib/select';
// import rison from 'rison';
// import { Checkbox } from 'antd';
import {
  t,
  SupersetClient,
  styled,
  isFeatureEnabled,
  FeatureFlag,
} from '@superset-ui/core';
import Chart, { Slice } from 'src/types/Chart';
import { getClientErrorObject } from 'src/utils/getClientErrorObject';
import withToasts from 'src/components/MessageToasts/withToasts';
import { loadTags } from 'src/components/Tags/utils';
import {
  addTag,
  deleteTaggedObjects,
  fetchTags,
  OBJECT_TYPES,
} from 'src/features/tags/tags';
import TagType from 'src/types/TagType';
import 'antd/dist/antd.css';
import CollaboratorModal from './CollaboratorModal'; // 新增的管理协作者弹窗组件


export type PropertiesModalProps = {
  slice: Slice;
  show: boolean;
  onHide: () => void;
  onSave: (chart: Chart) => void;
  permissionsError?: string;
  existingOwners?: SelectValue;
  addSuccessToast: (msg: string) => void;
};

const FormItem = AntdForm.Item;

const StyledFormItem = styled(AntdForm.Item)`
  margin-bottom: 0;
`;

const StyledHelpBlock = styled.span`
  margin-bottom: 0;
`;

const CollaboratorSection = styled.div`
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  margin-right: 40px; /* 向右移动 */
`;

function PropertiesModal({
  slice,
  onHide,
  onSave,
  show,
  addSuccessToast,
}: PropertiesModalProps) {
  const [submitting, setSubmitting] = useState(false);
  const [form] = AntdForm.useForm();
  // values of form inputs
  const [name, setName] = useState(slice.slice_name || '');
  const [selectedOwners, setSelectedOwners] = useState<
    { value: number; label: string }[] | { value: number; label: string } | null
  >(null);

  const [tags, setTags] = useState<TagType[]>([]);
  const [showCollaboratorModal, setShowCollaboratorModal] = useState(false);

  const handleOpenCollaboratorModal = () => setShowCollaboratorModal(true);
  const handleCloseCollaboratorModal = () => setShowCollaboratorModal(false);


  // // 新增状态：用户和角色权限
  // const [userPermissions, setUserPermissions] = useState<
  //   { userId: number; userName: string; permissions: ('read' | 'edit')[] }[]
  // >([]);
  //
  // const [rolePermissions, setRolePermissions] = useState<
  //   { roleId: number; roleName: string; permissions: ('read' | 'edit')[] }[]
  // >([]);


  const tagsAsSelectValues = useMemo(() => {
    const selectTags = tags.map(tag => ({
      value: tag.name,
      label: tag.name,
      key: tag.name,
    }));
    return selectTags;
  }, [tags.length]);

  function showError({ error, statusText, message }: any) {
    let errorText = error || statusText || t('An error has occurred');
    if (message === 'Forbidden') {
      errorText = t('你没有权限去修改别人的图表');
    }
    Modal.error({
      title: t('Error'),
      content: errorText,
      okButtonProps: { danger: true, className: 'btn-danger' },
    });
  }

  const fetchChartOwners = useCallback(
    async function fetchChartOwners() {
      try {
        const response = await SupersetClient.get({
          endpoint: `/api/v1/chart/${slice.slice_id}`,
        });
        const chart = response.json.result;
        setSelectedOwners(
          chart?.owners?.map((owner: any) => ({
            value: owner.id,
            label: `${owner.first_name} ${owner.last_name}`,
          })),
        );
      } catch (response) {
        const clientError = await getClientErrorObject(response);
        showError(clientError);
      }
    },
    [slice.slice_id],
  );

  // const loadRoleOptions = useMemo(
  //   () => async (input = '', page: number, pageSize: number) => {
  //     try {
  //       // 使用 rison 生成查询参数
  //       const params = rison.encode({
  //         filter: input, // 输入筛选条件
  //         page, // 当前页码
  //         page_size: pageSize, // 每页大小
  //       });
  //
  //       // 调用后端新接口
  //       const response = await SupersetClient.get({
  //         endpoint: `/api/v1/rowlevelsecurity/related/roles?q=${params}`, // 替换为新接口
  //       });
  //
  //       // 格式化返回数据
  //       return {
  //         data: response.json.result.map((item: { text: string; value: number }) => ({
  //           value: item.value,
  //           label: item.text,
  //         })),
  //         totalCount: response.json.count, // 从响应中获取总数
  //       };
  //     } catch (error) {
  //       console.error('Error fetching roles:', error);
  //       return { data: [], totalCount: 0 };
  //     }
  //   },
  //   [],
  // );


  // const loadOptions = useMemo(
  //   () =>
  //     async (input = '', page: number, pageSize: number) => {
  //       const query = rison.encode({
  //         filter: input,
  //         page,
  //         page_size: pageSize,
  //       });
  //       const response = await SupersetClient.get({
  //         endpoint: `/api/v1/chart/related/owners?q=${query}`,
  //       });
  //       return {
  //         data: response.json.result
  //           .filter((item: { extra: { active: boolean } }) => item.extra.active)
  //           .map((item_1: { value: number; text: string }) => ({
  //             value: item_1.value,
  //             label: item_1.text,
  //           })),
  //         totalCount: response.json.count,
  //       };
  //     },
  //   [],
  // );

  const updateTags = (oldTags: TagType[], newTags: TagType[]) => {
    // update the tags for this object
    // add tags that are in new tags, but not in old tags
    // eslint-disable-next-line array-callback-return
    newTags.map((tag: TagType) => {
      if (!oldTags.some(t => t.name === tag.name)) {
        addTag(
          {
            objectType: OBJECT_TYPES.CHART,
            objectId: slice.slice_id,
            includeTypes: false,
          },
          tag.name,
          () => {},
          () => {},
        );
      }
    });
    // delete tags that are in old tags, but not in new tags
    // eslint-disable-next-line array-callback-return
    oldTags.map((tag: TagType) => {
      if (!newTags.some(t => t.name === tag.name)) {
        deleteTaggedObjects(
          {
            objectType: OBJECT_TYPES.CHART,
            objectId: slice.slice_id,
          },
          tag,
          () => {},
          () => {},
        );
      }
    });
  };

  const onSubmit = async (values: {
    certified_by?: string;
    certification_details?: string;
    description?: string;
    cache_timeout?: number;
  }) => {
    setSubmitting(true);

    const {
      certified_by: certifiedBy,
      certification_details: certificationDetails,
      description,
      cache_timeout: cacheTimeout,
    } = values;

    const payload: { [key: string]: any } = {
      slice_name: name || 'Default Name',
      description: description || null,
      cache_timeout: cacheTimeout || null,
      certified_by: certifiedBy || null,
      slice_id: slice.slice_id,
      certification_details:
        certifiedBy && certificationDetails ? certificationDetails : null,
    };

    if (Array.isArray(selectedOwners)) {
      payload.owners = selectedOwners.map(o => o.value);
    } else if (selectedOwners) {
      payload.owners = [selectedOwners.value];
    } else {
      payload.owners = [];
    }

    if (isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM)) {
      // update tags
      try {
        fetchTags(
          {
            objectType: OBJECT_TYPES.CHART,
            objectId: slice.slice_id,
            includeTypes: false,
          },
          (currentTags: TagType[]) => updateTags(currentTags, tags),
          error => {
            showError(error);
          },
        );
      } catch (error) {
        showError(error);
      }
    }

    // if (userPermissions.length > 0) {
    //   payload.user_permissions = userPermissions.map(up => ({
    //     userId: up.userId,
    //     permissions: up.permissions.filter(p => p === 'read' || p === 'edit'), // 确保权限格式正确
    //   }));
    // }
    //
    // if (rolePermissions.length > 0) {
    //   payload.role_permissions = rolePermissions.map(rp => ({
    //     roleId: rp.roleId,
    //     permissions: rp.permissions.filter(p => p === 'read' || p === 'edit'),
    //   }));
    // }

    // 移除空字段
    Object.keys(payload).forEach(key => {
      if (payload[key] === null || payload[key] === undefined) {
        delete payload[key];
      }
    });

    console.log('Payload:', payload);

    try {
      const res = await SupersetClient.put({
        endpoint: `/api/v1/chart/${slice.slice_id}`,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      console.log('Response:', res);

      const updatedChart = {
        ...payload,
        ...res.json.result,
        tags,
        id: slice.slice_id,
        owners: selectedOwners,
      };

      onSave(updatedChart);
      addSuccessToast(t('Chart properties updated'));
      onHide();
    } catch (error) {
      const clientError = await getClientErrorObject(error);
      console.error('Request failed:', clientError);
      showError(clientError);
    }

    setSubmitting(false);
  };


  // const ownersLabel = t('Owners');

  // get the owners of this slice
  useEffect(() => {
    fetchChartOwners();
  }, [fetchChartOwners]);

  // update name after it's changed in another modal
  useEffect(() => {
    setName(slice.slice_name || '');
  }, [slice.slice_name]);

  useEffect(() => {
    if (!isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM)) return;
    try {
      fetchTags(
        {
          objectType: OBJECT_TYPES.CHART,
          objectId: slice.slice_id,
          includeTypes: false,
        },
        (tags: TagType[]) => setTags(tags),
        error => {
          showError(error);
        },
      );
    } catch (error) {
      showError(error);
    }
  }, [slice.slice_id]);

  const handleChangeTags = (values: { label: string; value: number }[]) => {
    // triggered whenever a new tag is selected or a tag was deselected
    // on new tag selected, add the tag

    const uniqueTags = [...new Set(values.map(v => v.label))];
    setTags([...uniqueTags.map(t => ({ name: t }))]);
  };

  const handleClearTags = () => {
    setTags([]);
  };

  return (
    <Modal
      show={show}
      onHide={onHide}
      title={t('Edit Chart Properties')}
      footer={
        <>
          <Button
            data-test="properties-modal-cancel-button"
            htmlType="button"
            buttonSize="small"
            onClick={onHide}
            cta
          >
            {t('Cancel')}
          </Button>
          <Button
            data-test="properties-modal-save-button"
            htmlType="submit"
            buttonSize="small"
            buttonStyle="primary"
            onClick={form.submit}
            disabled={submitting || !name || slice.is_managed_externally}
            tooltip={
              slice.is_managed_externally
                ? t(
                    "This chart is managed externally, and can't be edited in Superset",
                  )
                : ''
            }
            cta
          >
            {t('Save')}
          </Button>
        </>
      }
      responsive
      wrapProps={{ 'data-test': 'properties-edit-modal' }}
    >
      <AntdForm
        form={form}
        onFinish={onSubmit}
        layout="vertical"
        initialValues={{
          name: slice.slice_name || '',
          description: slice.description || '',
          cache_timeout: slice.cache_timeout != null ? slice.cache_timeout : '',
          certified_by: slice.certified_by || '',
          certification_details:
            slice.certified_by && slice.certification_details
              ? slice.certification_details
              : '',
        }}
      >
        <Row gutter={16}>
          <Col xs={24} md={12}>
            <h3>{t('Basic information')}</h3>
            <FormItem label={t('Name')} required>
              <Input
                aria-label={t('Name')}
                name="name"
                data-test="properties-modal-name-input"
                type="text"
                value={name}
                onChange={(event: React.ChangeEvent<HTMLInputElement>) =>
                  setName(event.target.value ?? '')
                }
              />
            </FormItem>
            <FormItem>
              <StyledFormItem label={t('Description')} name="description">
                <TextArea rows={3} style={{ maxWidth: '100%' }} />
              </StyledFormItem>
              <StyledHelpBlock className="help-block">
                {t(
                  'The description can be displayed as widget headers in the dashboard view. Supports markdown.',
                )}
              </StyledHelpBlock>
            </FormItem>
            <h3>{t('Certification')}</h3>
            <FormItem>
              <StyledFormItem label={t('Certified by')} name="certified_by">
                <Input aria-label={t('Certified by')} />
              </StyledFormItem>
              <StyledHelpBlock className="help-block">
                {t('Person or group that has certified this chart.')}
              </StyledHelpBlock>
            </FormItem>
            <FormItem>
              <StyledFormItem
                label={t('Certification details')}
                name="certification_details"
              >
                <Input aria-label={t('Certification details')} />
              </StyledFormItem>
              <StyledHelpBlock className="help-block">
                {t(
                  'Any additional detail to show in the certification tooltip.',
                )}
              </StyledHelpBlock>
            </FormItem>
          </Col>
          <Col xs={24} md={12}>
            <h3>{t('Configuration')}</h3>
            <FormItem>
              <StyledFormItem label={t('Cache timeout')} name="cache_timeout">
                <Input aria-label="Cache timeout" />
              </StyledFormItem>
              <StyledHelpBlock className="help-block">
                {t(
                  "Duration (in seconds) of the caching timeout for this chart. Set to -1 to bypass the cache. Note this defaults to the dataset's timeout if undefined.",
                )}
              </StyledHelpBlock>
            </FormItem>

            {isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM) && (
              <h3 css={{ marginTop: '1em' }}>{t('Tags')}</h3>
            )}
            {isFeatureEnabled(FeatureFlag.TAGGING_SYSTEM) && (
              <FormItem>
                <AsyncSelect
                  ariaLabel="Tags"
                  mode="multiple"
                  value={tagsAsSelectValues}
                  options={loadTags}
                  onChange={handleChangeTags}
                  onClear={handleClearTags}
                  allowClear
                />
                <StyledHelpBlock className="help-block">
                  {t('A list of tags that have been applied to this chart.')}
                </StyledHelpBlock>
              </FormItem>
            )}
          </Col>
        </Row>
        <Row gutter={16} style={{ marginTop: '1em' }}>
          <Col span={24}>
            <CollaboratorSection>
              <h3 style={{ marginBottom: '8px' }}>{t('Manage Collaborators')}</h3>
              <Button type="primary" onClick={handleOpenCollaboratorModal}>
                {t('Manage Collaborators')}
              </Button>
            </CollaboratorSection>
          </Col>
        </Row>
      </AntdForm>

      {/* 管理协作者弹窗 */}
      <CollaboratorModal
        visible={showCollaboratorModal}
        onClose={handleCloseCollaboratorModal}
        chartId={slice.slice_id}
      />
    </Modal>
  );
}

export default withToasts(PropertiesModal);
