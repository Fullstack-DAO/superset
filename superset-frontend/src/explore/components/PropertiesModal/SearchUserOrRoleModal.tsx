import React, { useState, useEffect } from 'react';
import { Modal, Input, Button, Spin, List, message } from 'antd';
import { SupersetClient, t } from '@superset-ui/core';
import { InboxOutlined } from '@ant-design/icons';

interface Collaborator {
  id: number;
  name: string;
  type: 'user' | 'role'; // 统一为 'user' | 'role'
  permission: string;
  key: string;
}

interface SearchUserOrRoleModalProps {
  visible: boolean;
  onClose: () => void;
  onAdd: (collaborator: Collaborator) => void;
  existingCollaborators?: { id: number; type: 'user' | 'role' }[];
  chartId: number;
}

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

  useEffect(() => {
    if (!chartId) {
      console.error('chartId 未定义，请检查父组件是否正确传递 chartId');
    }
  }, [chartId]);

  // 搜索用户或角色
  const handleSearch = async (): Promise<void> => {
    if (!searchValue.trim()) {
      setSearchResults([]);
      return;
    }

    setLoading(true);
    try {
      const res = await SupersetClient.get({
        endpoint: `/api/v1/user_or_role/?search=${encodeURIComponent(searchValue)}`,
      });

      // 假设 SupersetClient 在非 2xx 响应时会抛出错误
      const { result } = res.json;

      if (!result || (!result.users && !result.roles)) {
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

  // 添加协作者
  const handleAdd = async (item: SearchResultItem) => {
    if (!chartId) {
      message.error('chartId 未定义，无法添加协作者');
      return;
    }

    try {
      const res = await SupersetClient.post({
        endpoint: `/api/v1/chart/${chartId}/add-collaborator`,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: item.id,
          type: item.type,
        }),
      });

      // 假设 SupersetClient 在非 2xx 响应时会抛出错误
      const { json } = res;

      message.success(json.message || '添加成功');

      const collaborator: Collaborator = {
        id: item.id,
        name: item.name,
        type: item.type,
        permission: '可阅读',
        key: `${item.id}-${item.type}`,
      };

      onAdd(collaborator);
      onClose(); // 关闭搜索模态框
    } catch (error: any) {
      console.error('添加协作者时发生错误:', error);
      const errorMessage =
        error?.response?.json?.message || '添加失败，请稍后重试';
      message.error(errorMessage);
    }
  };

  return (
    <Modal
      title={t('搜索用户或角色')}
      visible={visible}
      onCancel={onClose}
      footer={null}
    >
      <Input.Search
        placeholder={t('请输入用户名或角色名')}
        enterButton={t('搜索')}
        value={searchValue}
        onChange={(e) => setSearchValue(e.target.value)}
        onSearch={handleSearch}
      />
      {loading ? (
        <Spin tip={t('加载中...')} />
      ) : searchResults.length === 0 ? (
        <div style={{ textAlign: 'center', marginTop: 16 }}>
          <InboxOutlined style={{ fontSize: 48, color: '#ccc' }} />
          <p>{t('暂无数据')}</p>
        </div>
      ) : (
        <List
          dataSource={searchResults}
          renderItem={(item) => (
            <List.Item>
              <span>
                {item.name} ({item.type === 'user' ? '用户' : '角色'})
              </span>
              <Button
                type="link"
                onClick={() => handleAdd(item)}
                style={{ marginLeft: 'auto' }}
              >
                {t('添加')}
              </Button>
            </List.Item>
          )}
        />
      )}
    </Modal>
  );
};

export default SearchUserOrRoleModal;
