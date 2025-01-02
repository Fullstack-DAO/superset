import React, { useState } from 'react';
import { Modal, Input, Button, Spin, List } from 'antd';
import { SupersetClient, t } from '@superset-ui/core';

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

      // 直接使用 response 数据
      const data: any = response; // response 已经是 JSON 对象
      const { result } = data || {};

      if (!result || (!result.users && !result.roles)) {
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
      title={t('搜索用户或角色')}
      visible={visible}
      onCancel={onClose}
      footer={[
        <Button key="cancel" onClick={onClose}>
          {t('取消')}
        </Button>,
      ]}
    >
      <Input.Search
        placeholder={t('输入用户名或角色名进行搜索')}
        value={searchValue}
        onChange={(e) => setSearchValue(e.target.value)}
        onSearch={handleSearch}
        enterButton
      />
      {loading ? (
        <Spin tip={t('加载中...')} />
      ) : (
        <List
          bordered
          dataSource={searchResults}
          renderItem={(item) => (
            <List.Item
              actions={[
                <Button
                  type="link"
                  onClick={() => {
                    onAdd(item);
                    onClose();
                  }}
                >
                  {t('添加')}
                </Button>,
              ]}
            >
              {`${item.name} (${item.type})`}
            </List.Item>
          )}
        />
      )}
    </Modal>
  );
};

export default SearchUserOrRoleModal;
