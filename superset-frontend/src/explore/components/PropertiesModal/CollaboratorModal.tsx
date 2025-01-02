import React, { useState, useEffect } from 'react';
import { Modal, Button, Dropdown, Menu, Spin } from 'antd';
import { UserOutlined, PlusOutlined, DownOutlined } from '@ant-design/icons';
import styled from '@emotion/styled';
import { SupersetClient, t } from '@superset-ui/core';

// 定义接口返回的协作者类型
interface ApiCollaborator {
  id: number;
  name: string;
  type: 'user' | 'role'; // 接口返回的类型
  permission: string;
}

// 定义前端展示的协作者类型
interface Collaborator {
  id: number;
  name: string;
  type: '用户' | '角色'; // 映射后的类型
  permission: string;
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

const DropdownMenu = styled(Dropdown)`
  min-width: 150px;
`;

const CollaboratorModal: React.FC<CollaboratorModalProps> = ({
                                                               visible,
                                                               onClose,
                                                               chartId,
                                                             }) => {
  const [collaborators, setCollaborators] = useState<Collaborator[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (visible && chartId) {
      fetchCollaborators();
    }
  }, [visible, chartId]);

  // 获取协作者信息
  const fetchCollaborators = async (): Promise<void> => {
    setLoading(true);
    try {
      // 获取原始 response
      const response = await SupersetClient.get({
        endpoint: `/api/v1/chart/${chartId}/access-info`,
      });

      // 确保 response.json 方法可以正确调用
      if (typeof response.json === 'function') {
        const { result } = (await response.json()) as { result: ApiCollaborator[] };

        console.log('API 返回的数据:', result);

        // 更新协作者数据
        setCollaborators(
          result.map((item) => ({
            id: item.id,
            name: item.name,
            type: item.type === 'user' ? '用户' : '角色',
            permission: item.permission || '可阅读',
          })),
        );
      } else {
        console.error('response.json 方法不可用');
      }
    } catch (error) {
      console.error('Error fetching collaborators:', error);
    } finally {
      setLoading(false);
    }
  };




  // 更新协作者权限
  const handlePermissionChange = (id: number, permission: string) => {
    setCollaborators((prev) =>
      prev.map((c) => (c.id === id ? { ...c, permission } : c)),
    );
  };

  // 删除协作者
  const handleRemoveCollaborator = (id: number) => {
    setCollaborators((prev) => prev.filter((c) => c.id !== id));
  };

  // 权限菜单
  const permissionMenu = (id: number) => (
    <Menu
      onClick={({ key }) => {
        if (key === '移除') {
          handleRemoveCollaborator(id);
        } else {
          handlePermissionChange(id, key as string);
        }
      }}
    >
      <Menu.Item key="可管理">{t('可管理')}</Menu.Item>
      <Menu.Item key="可编辑">{t('可编辑')}</Menu.Item>
      <Menu.Item key="可阅读">{t('可阅读')}</Menu.Item>
      <Menu.Item key="移除" danger>
        {t('移除')}
      </Menu.Item>
    </Menu>
  );

  return (
    <Modal
      title={t('管理协作者')}
      visible={visible}
      onCancel={onClose}
      footer={[
        <Button key="cancel" onClick={onClose}>
          {t('取消')}
        </Button>,
        <Button key="save" type="primary" onClick={onClose}>
          {t('保存')}
        </Button>,
      ]}
    >
      {loading ? (
        <Spin tip={t('加载中...')} />
      ) : (
        <CollaboratorContainer>
          {collaborators.length === 0 ? (
            <div>{t('暂无协作者')}</div>
          ) : (
            collaborators.map((collaborator) => (
              <CollaboratorItem key={collaborator.id}>
                <CollaboratorInfo>
                  <div className="avatar">
                    <UserOutlined />
                  </div>
                  <div className="name">{collaborator.name}</div>
                  <div style={{ marginLeft: '8px', color: '#888' }}>
                    {collaborator.type}
                  </div>
                </CollaboratorInfo>
                <DropdownMenu
                  overlay={permissionMenu(collaborator.id)}
                  trigger={['click']}
                >
                  <Button>
                    {collaborator.permission} <DownOutlined />
                  </Button>
                </DropdownMenu>
              </CollaboratorItem>
            ))
          )}
          <Button
            type="dashed"
            icon={<PlusOutlined />}
            style={{ width: '100%', marginTop: 12 }}
            onClick={() => console.log('添加协作者功能未实现')}
          >
            {t('添加协作者')}
          </Button>
        </CollaboratorContainer>
      )}
    </Modal>
  );
};

export default CollaboratorModal;
