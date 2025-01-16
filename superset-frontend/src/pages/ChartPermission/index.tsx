import React, { useState, useEffect } from 'react';

import { useParams } from 'react-router-dom';

interface Collaborator {
  id: string;
  name: string;
  role: string;
}

const roles = ['可管理', '可编辑', '可阅读'];

const ChartPermission: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [collaborators, setCollaborators] = useState<Collaborator[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // 模拟获取协作者数据
    const fetchCollaborators = async () => {
      try {
        setLoading(true);
        const response = await fetch(`/api/chart/permission/${id}`); // 替换为实际 API
        if (!response.ok) {
          throw new Error('Failed to fetch collaborators');
        }
        const data = await response.json();
        setCollaborators(data.collaborators);
      } catch (err) {
        setError('无法获取协作者数据');
      } finally {
        setLoading(false);
      }
    };

    fetchCollaborators();
  }, [id]);

  const handleRoleChange = (collaboratorId: string, newRole: string) => {
    setCollaborators(prev =>
      prev.map(c => (c.id === collaboratorId ? { ...c, role: newRole } : c)),
    );

    // 调用后端 API 更新权限
    fetch(`/api/chart/permission/${id}/update`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ collaboratorId, newRole }),
    }).catch(err => console.error('Failed to update role:', err));
  };

  const handleAddCollaborator = () => {
    // 示例：添加协作者的逻辑
    const newCollaborator = {
      id: `${Date.now()}`,
      name: '新协作者',
      role: '可阅读',
    };
    setCollaborators(prev => [...prev, newCollaborator]);

    // 调用后端 API 添加协作者
    fetch(`/api/chart/permission/${id}/add`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(newCollaborator),
    }).catch(err => console.error('Failed to add collaborator:', err));
  };

  if (loading) {
    return <div>加载中...</div>;
  }

  if (error) {
    return <div>{error}</div>;
  }

  return (
    <div className="chart-permission-container">
      <h2>管理协作者</h2>
      <ul>
        {collaborators.map(collaborator => (
          <li key={collaborator.id} className="collaborator-item">
            <span className="collaborator-name">{collaborator.name}</span>
            <select
              value={collaborator.role}
              onChange={e => handleRoleChange(collaborator.id, e.target.value)}
            >
              {roles.map(role => (
                <option key={role} value={role}>
                  {role}
                </option>
              ))}
            </select>
          </li>
        ))}
      </ul>
      <button
        type="button"  // 添加 type 属性
        onClick={handleAddCollaborator}
      >
        添加协作者
      </button>
    </div>
  );
};

export default ChartPermission;
