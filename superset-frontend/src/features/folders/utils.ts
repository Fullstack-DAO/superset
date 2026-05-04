export type FolderLike = {
  id: string;
  name: string;
  parentId: string | null;
  fullPath: string;
};

export type FolderTreeNode<T extends FolderLike> = T & {
  children: FolderTreeNode<T>[];
};

export type FolderCascaderOption = {
  value: string;
  label: string;
  disabled?: boolean;
  children?: FolderCascaderOption[];
};

export type FolderTreeSelectNode = {
  title: string;
  value: string;
  key: string;
  fullPathLabel: string;
  disabled?: boolean;
  disableCheckbox?: boolean;
  children?: FolderTreeSelectNode[];
};

export type FolderTreeSelectValue = {
  value: string;
  label: string;
};

const getFolderDisplayPath = <T extends FolderLike>(folder: T) =>
  folder.fullPath || folder.name || folder.id;

const sortFolders = <T extends FolderLike>(folders: T[]) =>
  [...folders].sort((left, right) =>
    getFolderDisplayPath(left).localeCompare(getFolderDisplayPath(right)),
  );

export const getFolderMap = <T extends FolderLike>(folders: T[]) =>
  new Map(folders.map(folder => [folder.id, folder]));

export const buildFolderTree = <T extends FolderLike>(
  folders: T[],
): FolderTreeNode<T>[] => {
  const sortedFolders = sortFolders(folders);
  const treeNodeMap = new Map<string, FolderTreeNode<T>>(
    sortedFolders.map(folder => [folder.id, { ...folder, children: [] }]),
  );
  const roots: FolderTreeNode<T>[] = [];

  sortedFolders.forEach(folder => {
    const node = treeNodeMap.get(folder.id);
    if (!node) {
      return;
    }

    if (folder.parentId) {
      const parent = treeNodeMap.get(folder.parentId);
      if (parent) {
        parent.children.push(node);
        return;
      }
    }

    roots.push(node);
  });

  return roots;
};

export const getFolderPathIds = <T extends FolderLike>(
  folderId: string,
  folders: T[],
): string[] => {
  const folderMap = getFolderMap(folders);
  const pathIds: string[] = [];
  let current = folderMap.get(folderId);

  while (current) {
    pathIds.unshift(current.id);
    current = current.parentId ? folderMap.get(current.parentId) : undefined;
  }

  return pathIds;
};

export const getFolderValuePaths = <T extends FolderLike>(
  folderIds: string[],
  folders: T[],
) =>
  folderIds
    .map(folderId => getFolderPathIds(folderId, folders))
    .filter(pathIds => pathIds.length > 0);

export const getDescendantFolders = <T extends FolderLike>(
  folderId: string,
  folders: T[],
): T[] => {
  const byParent = new Map<string | null, T[]>();

  folders.forEach(folder => {
    const siblings = byParent.get(folder.parentId) || [];
    siblings.push(folder);
    byParent.set(folder.parentId, siblings);
  });

  const descendants: T[] = [];
  const queue = [folderId];

  while (queue.length) {
    const currentFolderId = queue.shift();
    if (!currentFolderId) {
      continue;
    }

    const currentFolder = folders.find(folder => folder.id === currentFolderId);
    if (currentFolder) {
      descendants.push(currentFolder);
    }

    (byParent.get(currentFolderId) || []).forEach(child => {
      queue.push(child.id);
    });
  }

  return descendants;
};

export const buildFolderCascaderOptions = <T extends FolderLike>(
  folders: T[],
  disabledFolderIds: string[] = [],
): FolderCascaderOption[] => {
  const disabledIdSet = new Set(disabledFolderIds);

  const buildOptions = (
    nodes: FolderTreeNode<T>[],
  ): FolderCascaderOption[] =>
    nodes.map(node => ({
      value: node.id,
      label: node.name || getFolderDisplayPath(node),
      disabled: disabledIdSet.has(node.id),
      children: node.children.length ? buildOptions(node.children) : undefined,
    }));

  return buildOptions(buildFolderTree(folders));
};

export const buildFolderTreeSelectData = <T extends FolderLike>(
  folders: T[],
  disabledFolderIds: string[] = [],
): FolderTreeSelectNode[] => {
  const disabledIdSet = new Set(disabledFolderIds);

  const buildNodes = (
    nodes: FolderTreeNode<T>[],
  ): FolderTreeSelectNode[] =>
    nodes.map(node => ({
      title: node.name || getFolderDisplayPath(node),
      value: node.id,
      key: node.id,
      fullPathLabel: getFolderDisplayPath(node),
      disabled: disabledIdSet.has(node.id),
      children: node.children.length ? buildNodes(node.children) : undefined,
    }));

  return buildNodes(buildFolderTree(folders));
};

export const buildFolderTreeSelectValues = <T extends FolderLike>(
  folderIds: string[],
  folders: T[],
): FolderTreeSelectValue[] => {
  const folderMap = getFolderMap(folders);
  return Array.from(new Set(folderIds.filter(folderId => folderMap.has(folderId)))).map(
    folderId => {
      const folder = folderMap.get(folderId)!;
      return {
        value: folder.id,
        label: getFolderDisplayPath(folder),
      };
    },
  );
};

export const getFolderAncestorMenuKeys = <T extends FolderLike>(
  folderId: string,
  folders: T[],
  toMenuKey: (folderId: string) => string,
) => getFolderPathIds(folderId, folders).map(pathFolderId => toMenuKey(pathFolderId));

export const getFolderExpandedKeys = <T extends FolderLike>(
  folderIds: string[],
  folders: T[],
): string[] =>
  Array.from(
    new Set(
      folderIds.flatMap(folderId => getFolderPathIds(folderId, folders)),
    ),
  );
