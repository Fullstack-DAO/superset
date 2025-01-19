import React from 'react';
import { render, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';
import ChartPermission from './index';

describe('ChartPermission Component', () => {
  test('renders loading state', () => {
    render(
      <BrowserRouter>
        <ChartPermission />
      </BrowserRouter>,
    );
    expect(screen.getByText(/加载中.../i)).toBeInTheDocument();
  });

  test('renders error state', async () => {
    global.fetch = jest.fn(() =>
      Promise.resolve({
        ok: false,
      }),
    ) as jest.Mock;

    render(
      <BrowserRouter>
        <ChartPermission />
      </BrowserRouter>,
    );

    expect(await screen.findByText(/无法获取协作者数据/i)).toBeInTheDocument();
  });

  test('renders collaborators list', async () => {
    const mockData = {
      collaborators: [
        { id: '1', name: '张三', role: '可管理' },
        { id: '2', name: '李四', role: '可编辑' },
      ],
    };

    global.fetch = jest.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockData),
      }),
    ) as jest.Mock;

    render(
      <BrowserRouter>
        <ChartPermission />
      </BrowserRouter>,
    );

    expect(await screen.findByText(/张三/i)).toBeInTheDocument();
    expect(await screen.findByText(/李四/i)).toBeInTheDocument();
  });

  test('allows changing roles', async () => {
    const mockData = {
      collaborators: [{ id: '1', name: '张三', role: '可管理' }],
    };

    global.fetch = jest.fn(() =>
      Promise.resolve({
        ok: true,
        json: () => Promise.resolve(mockData),
      }),
    ) as jest.Mock;

    render(
      <BrowserRouter>
        <ChartPermission />
      </BrowserRouter>,
    );

    const select = (await screen.findByDisplayValue(
      /可管理/i,
    )) as HTMLSelectElement; // 断言为 HTMLSelectElement
    fireEvent.change(select, { target: { value: '可编辑' } });

    expect(select.value).toBe('可编辑'); // 现在可以正确访问 value 属性
  });
});
