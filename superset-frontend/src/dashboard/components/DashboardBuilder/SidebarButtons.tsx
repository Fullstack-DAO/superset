import React, { useCallback } from 'react';
import { styled } from '@superset-ui/core';

const ButtonContainer = styled.div`
  position: fixed;
  left: 0;
  top: 50%;
  transform: translateY(-50%);
  z-index: 10000;
  display: flex;
  flex-direction: column;
  background-color: white;
  border-radius: 0 4px 4px 0;
  box-shadow: 2px 2px 8px rgba(0, 0, 0, 0.15);
  border: 1px solid #e0e0e0;
  border-left: none;
  width: 32px;
`;

const StyledButton = styled.button`
  width: 32px;
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  background-color: white;
  color: #666;
  font-size: 16px;
  border: none;
  padding: 0;
  margin: 0;
  transition: all 0.2s ease;

  &:first-child {
    border-bottom: 1px solid #e0e0e0;
  }

  &:hover {
    background-color: #f5f5f5;
    color: ${({ theme }) => theme.colors.primary.base};
  }
`;

const SidebarButtons: React.FC = () => {
  const handleSidebarToggle = useCallback(() => {
    const selectors = ['.dashboard-builder-sidepane', '.dashboard-component-tabs'];
    selectors.forEach(selector => {
      const elements = document.querySelectorAll<HTMLElement>(selector);
      Array.from(elements).find(
        el => 
          window.getComputedStyle(el).display !== 'none' && 
          window.getComputedStyle(el).visibility !== 'hidden'
      )?.click();
    });
  }, []);

  const handleFilterToggle = useCallback(() => {
    const selectors = ['.dashboard-builder-sidepane', '.dashboard-component-tabs'];
    selectors.forEach(selector => {
      const elements = document.querySelectorAll<HTMLElement>(selector);
      Array.from(elements).find(
        el => 
          window.getComputedStyle(el).display !== 'none' && 
          window.getComputedStyle(el).visibility !== 'hidden'
      )?.click();
    });
  }, []);

  return (
    <ButtonContainer>
      <StyledButton
        onClick={handleSidebarToggle}
        title="折叠/展开侧边栏"
      >
        ≡
      </StyledButton>
      <StyledButton
        onClick={handleFilterToggle}
        title="筛选器"
      >
        ⊞
      </StyledButton>
    </ButtonContainer>
  );
};

export default SidebarButtons;
