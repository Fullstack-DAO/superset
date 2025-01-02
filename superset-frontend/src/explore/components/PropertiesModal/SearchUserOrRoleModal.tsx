import React, { useState } from 'react';
import { Modal, Input, Button, Spin, List } from 'antd';
import { SupersetClient, } from '@superset-ui/core';
import { InboxOutlined } from '@ant-design/icons';

interface SearchUserOrRoleModalProps {
  visible: boolean;
  onClose: () => void;
  onAdd: (item: { id: number; name: string; type: '用户' | '角色' }) => void;
}

interface SearchResultItem {
  id: number;
  name: string;
  type: '用户' | '角色';
}

const SearchUserOrRoleModal: React.FC<SearchUserOrRoleModalProps> = ({
                                                                       visible,
                                                                       onClose,
                                                                       onAdd,
                                                                     }) => {
  const [searchResults, setSearchResults] = useState<SearchResultItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [searchValue, setSearchValue] = useState('');

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

      // 直接解析返回的 result 数据
      const data = (response as any).json || response; // 如果有 json 字段直接使用它
      const result = data.result || {};

      if (!result.users && !result.roles) {
        setSearchResults([]);
        return;
      }

      // 合并用户和角色结果
      const results: SearchResultItem[] = [
        ...(result.users || []).map((user: { id: number; username: string }) => ({
          id: user.id,
          name: user.username,
          type: '用户',
        })),
        ...(result.roles || []).map((role: { id: number; name: string }) => ({
          id: role.id,
          name: role.name,
          type: '角色',
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
                onClick={() => onAdd(item)}
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
