import type { NetworkNode } from '@/data/mockData';

export interface PositionedNetworkNode extends NetworkNode {
  x: number;
  y: number;
}

export interface NetworkLayout {
  nodes: PositionedNetworkNode[];
  height: number;
}

export const NODE_RADIUS = 22;
export const MIN_NODE_GAP = 76;
const SIDE_PADDING = 60;
const VERTICAL_PADDING = 40;

const COLUMN_TYPES: ReadonlyArray<ReadonlyArray<NetworkNode['type']>> = [
  ['user'],
  ['device'],
  ['app', 'server'],
  ['database'],
];

/** Place nodes in typed columns, ignoring stored coordinates; height is max(minHeight, tallest column * gap + 80). */
export function layoutNodes(
  nodes: readonly NetworkNode[],
  width: number,
  minGap: number = MIN_NODE_GAP,
  minHeight = 0,
): NetworkLayout {
  const gap = Math.max(minGap, NODE_RADIUS * 2 + 20);
  const columns = COLUMN_TYPES
    .map((types, columnIndex) => nodes
      .filter((node) => (types as readonly string[]).includes(node.type)
        // Backend asset types are free-form; unknown ones join the app/server column.
        || (columnIndex === 2 && !COLUMN_TYPES.flat().includes(node.type)))
      .sort((a, b) => b.propagationRisk - a.propagationRisk || a.id.localeCompare(b.id)))
    .filter((column) => column.length > 0);

  const tallest = Math.max(0, ...columns.map((column) => column.length));
  const height = Math.max(minHeight, tallest * gap + VERTICAL_PADDING * 2);
  const innerWidth = Math.max(0, width - SIDE_PADDING * 2);
  const positioned: PositionedNetworkNode[] = [];

  columns.forEach((column, columnIndex) => {
    const x = columns.length === 1 ? width / 2 : SIDE_PADDING + (innerWidth * columnIndex) / (columns.length - 1);
    const step = Math.max(gap, (height - VERTICAL_PADDING * 2) / column.length);
    const top = (height - (column.length - 1) * step) / 2;
    column.forEach((node, index) => positioned.push({ ...node, x, y: top + index * step }));
  });

  return { nodes: positioned, height };
}
