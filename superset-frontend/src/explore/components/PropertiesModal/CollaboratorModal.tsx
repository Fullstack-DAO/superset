// CollaboratorModal.tsx
import React, { useState, useEffect } from 'react';
import { Modal, Button, Spin, message, Select} from 'antd';
import { UserOutlined, PlusOutlined } from '@ant-design/icons';
import styled from '@emotion/styled';
import { SupersetClient, t } from '@superset-ui/core';
import SearchUserOrRoleModal from './SearchUserOrRoleModal';

// 定义权限枚举
export enum Permission {
  CanRead = 'can_read',
  CanEdit = 'can_edit',
  CanAdd = 'can_add',
  CanDelete = 'can_delete',
}

// 定义请求体接口
interface ModifyPermissionsData {
  entity_type: 'user' | 'role';
  entity_id: number;
  permissions: Permission[];
  action: 'add' | 'remove'; // 使用原始字段名
}

// 定义前端展示的协作者类型
interface Collaborator {
  id: number;
  name: string;
  type: 'user' | 'role'; // 统一为 'user' | 'role'
  permissions: Permission[]; // 使用枚举
  key: string; // 唯一键值，确保 React 不重复
  isUpdating?: boolean; // 更新状态
  isCreator?: boolean; // 创建者状态
}

interface CollaboratorModalProps {
  visible: boolean;
  onClose: () => void;
  chartId: number;
}

// 样式组件
const CollaboratorContainer = styled.div`
  padding: 16px;
  max-height: 400px;
  overflow-y: auto;
  border: 1px solid #f0f0f0;
`;

const CollaboratorItem = styled.div`
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 12px;
  border-bottom: 1px solid #f0f0f0;
  padding-bottom: 12px;
`;

const CollaboratorInfo = styled.div`
  display: flex;
  align-items: center;

  .avatar {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    background-color: #f0f0f0;
    display: flex;
    align-items: center;
    justify-content: center;
    margin-right: 12px;
  }

  .name {
    font-weight: bold;
  }
`;

const CollaboratorModal: React.FC<CollaboratorModalProps> = ({
                                                               visible,
                                                               onClose,
                                                               chartId,
                                                             }) => {
  const [collaborators, setCollaborators] = useState<Collaborator[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchModalVisible, setSearchModalVisible] = useState(false);
  const [updatingIds, setUpdatingIds] = useState<Set<string>>(new Set());

  useEffect(() => {
    if (visible && chartId) {
      fetchCollaborators();
    }
  }, [visible, chartId]);

  // 获取协作者信息
  const fetchCollaborators = async () => {
    setLoading(true);
    try {
      const res = await SupersetClient.get({
        endpoint: `/api/v1/chart/${chartId}/access-info`,
      });

      const { result: access_info } = res.json;

      if (!access_info || !Array.isArray(access_info)) {
        console.error('API 返回的数据格式不正确:', res.json);
        setCollaborators([]);
        return;
      }

      // 映射协作者数据
      setCollaborators(
        access_info.map((item: { id: number; name: string; is_creator: boolean; permission: string; type: string }) => ({
          id: item.id,
          name: item.name,
          isCreator: item.is_creator,
          permissions: getPermissionsFromLabel(item.permission),
          type: item.type as 'user' | 'role',
          key: `${item.id}-${item.type}`,
        })),
      );
    } catch (error: any) {
      console.error('Error fetching collaborators:', error);
      message.error(t('无法获取协作者信息'));
      setCollaborators([]);
    } finally {
      setLoading(false);
    }
  };

  // 将权限标签转换为权限数组
  const getPermissionsFromLabel = (label: string): Permission[] => {
    switch (label) {
      case '可管理':
        return [Permission.CanRead, Permission.CanEdit, Permission.CanAdd, Permission.CanDelete];
      case '可编辑':
        return [Permission.CanRead, Permission.CanEdit];
      case '可阅读':
        return [Permission.CanRead];
      default:
        return [];
    }
  };

  // 将权限数组转换为权限标签
  const getPermissionLabel = (permissions: Permission[]): string => {
    if (
      permissions.includes(Permission.CanRead) &&
      permissions.includes(Permission.CanEdit) &&
      permissions.includes(Permission.CanAdd) &&
      permissions.includes(Permission.CanDelete)
    ) {
      return '可管理';
    }
    if (
      permissions.includes(Permission.CanRead) &&
      permissions.includes(Permission.CanEdit)
    ) {
      return '可编辑';
    }
    if (permissions.includes(Permission.CanRead)) {
      return '可阅读';
    }
    return '无权限';
  };

  // 添加协作者
  const handleAddCollaborator = async (newCollaborator: { id: number; name: string; type: 'user' | 'role' }) => {
    try {
      // 默认权限为 '可阅读'
      const permissionsToAdd = getPermissionsFromLabel('可阅读'); // ['can_read']

      const data: ModifyPermissionsData = {
        entity_type: newCollaborator.type,
        entity_id: newCollaborator.id,
        permissions: permissionsToAdd, // ['can_read']
        action: 'add', // 使用原始字段名
      };

      await SupersetClient.post({ // 使用 POST 方法
        endpoint: `/api/v1/chart/${chartId}/permissions/modify`,
        body: JSON.stringify(data),
        headers: {
          'Content-Type': 'application/json', // 设置 Content-Type
        },
      });

      // 更新本地状态
      setCollaborators((prev) => [
        ...prev,
        {
          id: newCollaborator.id,
          name: newCollaborator.name,
          type: newCollaborator.type,
          permissions: permissionsToAdd, // ['can_read']
          key: `${newCollaborator.id}-${newCollaborator.type}`,
        },
      ]);

      message.success(t('协作者添加成功'));
    } catch (error: any) {
      console.error('Error adding collaborator:', error);
      if (error.response?.json) {
        const errorMsg = await error.response.json();
        message.error(t(`添加协作者失败: ${errorMsg.errors[0].message}`));
      } else {
        message.error(t('添加协作者失败'));
      }
    }
  };

  // 更新协作者权限
  const handlePermissionChange = async (collaborator: Collaborator, newPermissions: Permission[]) => {
    const { key, type, id } = collaborator;  // 使用对象解构
    setUpdatingIds(prev => new Set(prev).add(key));

    try {
      const data: ModifyPermissionsData = {
        entity_type: type,
        entity_id: id,
        permissions: newPermissions,
        action: 'add'
      };

      await SupersetClient.post({
        endpoint: `/api/v1/chart/${chartId}/permissions/modify`,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      // 更新本地状态
      setCollaborators(prev =>
        prev.map(c =>
          c.key === key ? { ...c, permissions: newPermissions } : c
        )
      );

      message.success(t('权限更新成功'));
    } catch (error: any) {
      console.error('Error updating permissions:', error);
      if (error.response?.json) {
        const errorMsg = await error.response.json();
        message.error(t(`更新权限失败: ${errorMsg.errors[0].message}`));
      } else {
        message.error(t('更新权限失败'));
      }
    } finally {
      setUpdatingIds(prev => {
        const newSet = new Set(prev);
        newSet.delete(key);
        return newSet;
      });
    }
  };

  // 删除协作者
  const handleRemoveCollaborator = async (collaborator: Collaborator) => {
    const data: ModifyPermissionsData = {
      entity_type: collaborator.type,
      entity_id: collaborator.id,
      permissions: [],
      action: 'remove'
    };

    try {
      await SupersetClient.post({
        endpoint: `/api/v1/chart/${chartId}/permissions/modify`,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data),
      });

      setCollaborators(prev => 
        prev.filter(c => c.key !== collaborator.key)
      );
      message.success(t('协作者移除成功'));
    } catch (error: any) {
      console.error('Error removing collaborator:', error);
      if (error.response?.json) {
        const errorMsg = await error.response.json();
        message.error(t(`移除协作者失败: ${errorMsg.errors[0].message}`));
      } else {
        message.error(t('移除协作者失败'));
      }
    }
  };

  return (
    <>
      <Modal
        title={t('管理协作者')}
        visible={visible}
        onCancel={onClose}
        footer={null} // 移除底部按钮
      >
        {loading ? (
          <Spin tip={t('加载中...')} />
        ) : (
          <CollaboratorContainer>
            {collaborators.length === 0 ? (
              <div>{t('暂无协作者')}</div>
            ) : (
              collaborators.map((collaborator) => {
                const isUpdating = updatingIds.has(collaborator.key);

                return (
                  <CollaboratorItem key={collaborator.key}>
                    <CollaboratorInfo>
                      <div className="avatar">
                        <UserOutlined />
                      </div>
                      <div className="name">{collaborator.name}</div>
                      {collaborator.isCreator && <span style={{ color: 'blue', marginLeft: '8px' }}>创建者</span>}
                      <div style={{ marginLeft: '8px', color: '#888' }}>
                        {collaborator.type === 'user' ? t('用户') : t('角色')}
                      </div>
                    </CollaboratorInfo>
                    <Select
                      disabled={collaborator.isCreator}
                      defaultValue={getPermissionLabel(collaborator.permissions)}
                      onChange={(value) => {
                        if (value === '移除') {
                          Modal.confirm({
                            title: t('确定要移除这个协作者吗？'),
                            onOk: () => handleRemoveCollaborator(collaborator),
                            okText: t('确定'),
                            cancelText: t('取消'),
                            okButtonProps: { danger: true },
                          });
                        } else {
                          handlePermissionChange(collaborator, getPermissionsFromLabel(value));
                        }
                      }}
                    >
                      <Select.Option value="可管理">{t('可管理')}</Select.Option>
                      <Select.Option value="可编辑">{t('可编辑')}</Select.Option>
                      <Select.Option value="可阅读">{t('可阅读')}</Select.Option>
                      <Select.Option value="移除" style={{ color: 'red' }}>{t('移除')}</Select.Option>
                    </Select>
                    {isUpdating && <Spin size="small" style={{ marginLeft: 8 }} />}
                  </CollaboratorItem>
                );
              })
            )}
            <Button
              type="dashed"
              icon={<PlusOutlined />}
              style={{ width: '100%', marginTop: 12 }}
              onClick={() => setSearchModalVisible(true)}
            >
              {t('添加协作者')}
            </Button>
          </CollaboratorContainer>
        )}
      </Modal>
      <SearchUserOrRoleModal
        visible={searchModalVisible}
        onClose={() => setSearchModalVisible(false)}
        onAdd={handleAddCollaborator}
        chartId={chartId} // 传递 chartId
      />
    </>
  );
};

export default CollaboratorModal;
