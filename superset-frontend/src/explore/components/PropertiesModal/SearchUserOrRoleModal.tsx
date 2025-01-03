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
  onAdd: (collaborators: Collaborator[]) => void; // 改为支持批量添加协作者
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
                                                                       chartId,
                                                                     }) => {
  const [searchResults, setSearchResults] = useState<SearchResultItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchValue, setSearchValue] = useState('');
  const [selectedItems, setSelectedItems] = useState<Set<SearchResultItem>>(new Set());

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

  // 选择或取消选择协作者
  const toggleSelect = (item: SearchResultItem) => {
    setSelectedItems((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(item)) {
        newSet.delete(item);
      } else {
        newSet.add(item);
      }
      return newSet;
    });
  };

  // 批量添加协作者
  const handleBatchAdd = async () => {
    if (!chartId) {
      message.error('chartId 未定义，无法添加协作者');
      return;
    }

    const collaborators = Array.from(selectedItems).map((item) => ({
      id: item.id,
      name: item.name,
      type: item.type,
      permission: '可阅读',
      key: `${item.id}-${item.type}`,
    }));

    try {
      await Promise.all(
        collaborators.map((collaborator) =>
          SupersetClient.post({
            endpoint: `/api/v1/chart/${chartId}/add-collaborator`,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              id: collaborator.id,
              type: collaborator.type,
            }),
          }),
        ),
      );
      message.success('协作者添加成功');
      onAdd(collaborators);
      onClose();
    } catch (error: any) {
      console.error('批量添加协作者时发生错误:', error);
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
      footer={[
        <Button key="cancel" onClick={onClose}>
          {t('取消')}
        </Button>,
        <Button
          key="add"
          type="primary"
          onClick={handleBatchAdd}
          disabled={selectedItems.size === 0}
        >
          {t('添加选中')}
        </Button>,
      ]}
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
                type={selectedItems.has(item) ? 'primary' : 'default'}
                onClick={() => toggleSelect(item)}
                style={{ marginLeft: 'auto' }}
              >
                {selectedItems.has(item) ? t('取消选择') : t('选择')}
              </Button>
            </List.Item>
          )}
        />
      )}
    </Modal>
  );
};

export default SearchUserOrRoleModal;
