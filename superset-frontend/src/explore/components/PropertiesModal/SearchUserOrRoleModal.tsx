import React, { useState, useEffect } from 'react';
import { Modal, Input, Button, Spin, List, message } from 'antd';
import { SupersetClient } from '@superset-ui/core';
import { InboxOutlined } from '@ant-design/icons';

// 定义 Collaborator 类型
interface Collaborator {
  id: number;
  name: string;
  type: 'user' | 'role';
  permission: string;
  key: string;
}

// 定义 SearchUserOrRoleModalProps 接口
interface SearchUserOrRoleModalProps {
  visible: boolean;
  onClose: () => void;
  onAdd: (collaborator: Collaborator) => void; // 确保 onAdd 参数类型为 Collaborator
  existingCollaborators?: { id: number; type: 'user' | 'role' }[];
  chartId: number;
}

// 定义 SearchResultItem 类型
interface SearchResultItem {
  id: number;
  name: string;
  type: 'user' | 'role';
}

const SearchUserOrRoleModal: React.FC<SearchUserOrRoleModalProps> = ({
                                                                       visible,
                                                                       onClose,
                                                                       onAdd,
                                                                       existingCollaborators = [],
                                                                       chartId,
                                                                     }) => {
  const [searchResults, setSearchResults] = useState<SearchResultItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchValue, setSearchValue] = useState('');

  // 调试 chartId
  useEffect(() => {
    if (!chartId) {
      console.error('chartId 未定义，请检查父组件是否正确传递 chartId');
    } else {
      console.log('接收到的 chartId:', chartId);
    }
  }, [chartId]);

  const handleSearch = async (): Promise<void> => {
    if (!searchValue.trim()) {
      setSearchResults([]);
      return;
    }

    setLoading(true);
    try {
      const response = await SupersetClient.get({
        endpoint: `/api/v1/user_or_role/?search=${encodeURIComponent(searchValue)}`,
      });

      const data = (response as any).json || response;
      const result = data.result || {};

      if (!result.users && !result.roles) {
        setSearchResults([]);
        return;
      }

      const results: SearchResultItem[] = [
        ...(result.users || []).map((user: { id: number; username: string }) => ({
          id: user.id,
          name: user.username,
          type: 'user',
        })),
        ...(result.roles || []).map((role: { id: number; name: string }) => ({
          id: role.id,
          name: role.name,
          type: 'role',
        })),
      ];

      setSearchResults(results);
    } catch (error) {
      console.error('Error fetching search results:', error);
      setSearchResults([]);
    } finally {
      setLoading(false);
    }
  };

  const handleAdd = async (item: SearchResultItem) => {
    if (!chartId) {
      message.error('chartId 未定义，无法添加协作者');
      return;
    }

    try {
      // 假设 SupersetClient.post 返回 JsonResponse 类型
      const response = await SupersetClient.post({
        endpoint: `/api/v1/chart/${chartId}/add-collaborator`,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: item.id,
          type: item.type,
        }),
      });

      const data = (response as any).json || response;

      if (data.status === 200) {
        message.success(data.message);

        // 添加协作者
        const collaborator: Collaborator = {
          id: item.id,
          name: item.name,
          type: item.type,
          permission: '可读', // 默认权限
          key: `${item.id}-${item.type}`,
        };
        onAdd(collaborator);
      } else {
        message.warning(data.message || '添加失败，请稍后重试');
      }
    } catch (error: any) {
      console.error('添加协作者时发生错误:', error);

      const errorMessage =
        error?.response?.message || '添加失败，请稍后重试';
      message.error(errorMessage);
    }
  };

  return (
    <Modal
      title="搜索用户或角色"
      visible={visible}
      onCancel={onClose}
      footer={null}
    >
      <Input.Search
        placeholder="请输入用户名或角色名"
        enterButton
        value={searchValue}
        onChange={(e) => setSearchValue(e.target.value)}
        onSearch={handleSearch}
      />
      {loading ? (
        <Spin tip="加载中..." />
      ) : searchResults.length === 0 ? (
        <div style={{ textAlign: 'center', marginTop: 16 }}>
          <InboxOutlined style={{ fontSize: 48, color: '#ccc' }} />
          <p>No Data</p>
        </div>
      ) : (
        <List
          dataSource={searchResults}
          renderItem={(item) => (
            <List.Item>
              {item.name} ({item.type})
              <Button
                type="link"
                onClick={() => handleAdd(item)}
                style={{ marginLeft: 'auto' }}
              >
                添加
              </Button>
            </List.Item>
          )}
        />
      )}
    </Modal>
  );
};

export default SearchUserOrRoleModal;
