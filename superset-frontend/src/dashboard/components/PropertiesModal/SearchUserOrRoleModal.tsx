// SearchUserOrRoleModal.tsx
import React, { useState } from 'react';
import { Modal, Button, Input, List, Spin, message } from 'antd';
import { SupersetClient, t } from '@superset-ui/core';
import styled from '@emotion/styled';
import { UserOutlined } from "@ant-design/icons";

interface SearchUserOrRoleModalProps {
  visible: boolean;
  onClose: () => void;
  onAdd: (collaborator: { id: number; name: string; type: 'user' | 'role' }) => void;
  dashboardId: number;
}

const SearchContainer = styled.div`
  padding: 16px;
`;

const SearchUserOrRoleModal: React.FC<SearchUserOrRoleModalProps> = ({
                                                                       visible,
                                                                       onClose,
                                                                       onAdd,
                                                                       dashboardId,
                                                                     }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [results, setResults] = useState<{ id: number; name: string; type: 'user' | 'role' }[]>([]);
  const [loading, setLoading] = useState(false);

  const handleSearch = async (value: string) => {
    setSearchTerm(value);
    if (!value) {
      setResults([]);
      return;
    }
    setLoading(true);
    try {
      const res = await SupersetClient.get({
        endpoint: `/api/v1/dashboard/${dashboardId}/search-users-or-roles?query=${encodeURIComponent(value)}`,
      });
      setResults(res.json.result);
    } catch (error: any) {
      console.error('Error searching users or roles:', error);
      message.error(t('搜索用户或角色失败'));
    } finally {
      setLoading(false);
    }
  };

  const handleAdd = (item: { id: number; name: string; type: 'user' | 'role' }) => {
    onAdd(item);
    onClose();
  };

  return (
    <Modal
      title={t('搜索并添加协作者')}
      visible={visible}
      onCancel={onClose}
      footer={null}
    >
      <SearchContainer>
        <Input.Search
          placeholder={t('输入用户名或角色名进行搜索')}
          enterButton={t('搜索')}
          onSearch={handleSearch}
        />
        {loading ? (
          <Spin style={{ marginTop: 16 }} />
        ) : (
          <List
            style={{ marginTop: 16 }}
            bordered
            dataSource={results}
            renderItem={item => (
              <List.Item
                actions={[
                  <Button type="link" onClick={() => handleAdd(item)}>
                    {t('添加')}
                  </Button>,
                ]}
              >
                <List.Item.Meta
                  avatar={<UserOutlined />}
                  title={item.name}
                  description={item.type === 'user' ? t('用户') : t('角色')}
                />
              </List.Item>
            )}
          />
        )}
      </SearchContainer>
    </Modal>
  );
};

export default SearchUserOrRoleModal;
