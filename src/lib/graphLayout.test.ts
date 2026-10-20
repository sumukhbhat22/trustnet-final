import { describe, expect, it } from 'vitest';
import type { NetworkNode } from '@/data/mockData';
import { layoutNodes } from '@/lib/graphLayout';

const TYPES: NetworkNode['type'][] = ['user', 'device', 'app', 'server', 'database'];
const COLUMN: Record<string, number> = { user: 0, device: 1, app: 2, server: 2, database: 3, asset: 3 };
const R = 22;
const WIDTH = 800;
const GAP = 76;

function makeNodes(count: number): NetworkNode[] {
  return Array.from({ length: count }, (_, i) => ({
    id: `n${i}`,
    label: `Node ${i}`,
    type: TYPES[i % TYPES.length],
    x: 700 - i * 11,
    y: i * 3,
    compromised: i % 7 === 0,
    propagationRisk: (i * 37) % 101,
  }));
}

describe('layoutNodes', () => {
  it.each([15, 40, 1])('lays out %i nodes without overlap and inside bounds', (count) => {
    const nodes = makeNodes(count);
    const { nodes: placed, height } = layoutNodes(nodes, WIDTH, GAP, 260);

    expect(placed).toHaveLength(count);
    for (const node of placed) {
      expect(node.x).toBeGreaterThanOrEqual(R);
      expect(node.x).toBeLessThanOrEqual(WIDTH - R);
      expect(node.y).toBeGreaterThanOrEqual(R);
      expect(node.y).toBeLessThanOrEqual(height - R);
    }
    for (let i = 0; i < placed.length; i += 1) {
      for (let j = i + 1; j < placed.length; j += 1) {
        const distance = Math.hypot(placed[i].x - placed[j].x, placed[i].y - placed[j].y);
        expect(distance).toBeGreaterThanOrEqual(2 * R + 20);
      }
    }

    const counts = new Map<number, number>();
    nodes.forEach((n) => counts.set(COLUMN[n.type], (counts.get(COLUMN[n.type]) ?? 0) + 1));
    expect(height).toBeGreaterThanOrEqual(Math.max(...counts.values()) * GAP);
    expect(height).toBeGreaterThanOrEqual(260);
  });

  it('keeps column order by type and sorts each column by risk descending', () => {
    const { nodes: placed } = layoutNodes(makeNodes(15), WIDTH, GAP);
    const xByColumn = new Map<number, number>();
    for (const node of placed) {
      const column = COLUMN[node.type];
      xByColumn.set(column, node.x);
      expect(xByColumn.get(column)).toBe(node.x);
    }
    const xs = [0, 1, 2, 3].map((c) => xByColumn.get(c) as number);
    expect(xs).toEqual([...xs].sort((a, b) => a - b));

    const apps = placed.filter((n) => COLUMN[n.type] === 2).sort((a, b) => a.y - b.y);
    for (let i = 1; i < apps.length; i += 1) {
      expect(apps[i - 1].propagationRisk).toBeGreaterThanOrEqual(apps[i].propagationRisk);
    }
  });

  it('is deterministic and ignores stored coordinates', () => {
    const nodes = makeNodes(15);
    const moved = nodes.map((n) => ({ ...n, x: 5, y: 999 }));
    expect(layoutNodes(nodes, WIDTH, GAP)).toEqual(layoutNodes(nodes, WIDTH, GAP));
    expect(layoutNodes(moved, WIDTH, GAP).nodes.map((n) => [n.x, n.y])).toEqual(
      layoutNodes(nodes, WIDTH, GAP).nodes.map((n) => [n.x, n.y]),
    );
  });
});
