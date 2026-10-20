import { Suspense, lazy, useCallback, useMemo, useState } from 'react';
import { useSecurity } from '@/store/securityStore';
import type { NetworkNode, NetworkEdge } from '@/data/mockData';
import { layoutNodes, MIN_NODE_GAP, NODE_RADIUS } from '@/lib/graphLayout';
import { NODE_TOKENS, tone, truncateLabel } from '@/lib/graphTheme';
import { NetworkGraphLegend } from './NetworkGraphLegend';

const NetworkGraph3D = lazy(() => import('./NetworkGraph3D'));

const NODE_ICONS: Record<string, string> = { user: '👤', app: '🌐', device: '💻', asset: '🗄️', database: '🗄️', server: '🖥️' };

const edgePath = (from: { x: number; y: number }, to: { x: number; y: number }) => {
  // Same-column edges bow sideways so they do not run through intermediate nodes.
  if (from.x === to.x) {
    const bow = from.x + NODE_RADIUS * 2;
    return `M ${from.x},${from.y} C ${bow},${from.y} ${bow},${to.y} ${to.x},${to.y}`;
  }
  const mid = (from.x + to.x) / 2;
  return `M ${from.x},${from.y} C ${mid},${from.y} ${mid},${to.y} ${to.x},${to.y}`;
};

interface NetworkGraphProps {
  width?: number;
  height?: number;
  graphNodes?: NetworkNode[];
  graphEdges?: NetworkEdge[];
}

export const NetworkGraph2D = ({ width = 800, height = 0, graphNodes, graphEdges }: NetworkGraphProps) => {
  const { nodes: contextNodes, edges: contextEdges, isAttackSimulated } = useSecurity();
  const nodes = graphNodes ?? contextNodes;
  const edges = graphEdges ?? contextEdges;
  const [hoveredNode, setHoveredNode] = useState<string | null>(null);

  const layout = useMemo(() => layoutNodes(nodes, width, MIN_NODE_GAP, height), [nodes, width, height]);
  const viewHeight = layout.height;
  const byId = useMemo(() => new Map(layout.nodes.map((node) => [node.id, node])), [layout]);

  return (
    <div className="network-graph">
      <svg viewBox={`0 0 ${width} ${viewHeight}`} className="network-graph-svg w-full h-auto" role="img" aria-label="Network topology graph">
        <defs>
          <filter id="topology-amber-glow" filterUnits="userSpaceOnUse" x="0" y="0" width={width} height={viewHeight}>
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <filter id="topology-critical-glow" filterUnits="userSpaceOnUse" x="0" y="0" width={width} height={viewHeight}>
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <linearGradient id="topology-attack-gradient" gradientUnits="userSpaceOnUse" x1="0" y1="0" x2={width} y2="0">
            <stop offset="0%" stopColor={tone('threat-high')} />
            <stop offset="100%" stopColor={tone('threat-critical')} />
          </linearGradient>
        </defs>

        {edges.map((edge, index) => {
          const from = byId.get(edge.from);
          const to = byId.get(edge.to);
          if (!from || !to) return null;
          const path = edgePath(from, to);
          return (
            <g key={`${edge.from}-${edge.to}-${index}`}>
              <path
                d={path}
                fill="none"
                stroke={edge.attackPath ? 'url(#topology-attack-gradient)' : tone('threat-low', 0.35)}
                strokeWidth={edge.attackPath ? 2.5 : 1}
                strokeDasharray={edge.attackPath ? undefined : '4 6'}
                filter={edge.attackPath ? 'url(#topology-critical-glow)' : undefined}
              />
              {edge.attackPath && isAttackSimulated && (
                <path d={path} fill="none" stroke={tone('threat-critical')} strokeWidth="2.5" className="animate-attack-path" />
              )}
              <circle r="2.5" fill={edge.attackPath ? tone('threat-critical') : tone('threat-low')} opacity={edge.attackPath ? 1 : 0.65}>
                <animateMotion dur={`${2 + index * 0.25}s`} repeatCount="indefinite" path={path} />
              </circle>
            </g>
          );
        })}

        {layout.nodes.map((node) => {
          const isHovered = hoveredNode === node.id;
          const token = node.compromised ? 'threat-critical' : NODE_TOKENS[node.type] ?? 'threat-low';
          const arcRadius = NODE_RADIUS + 4;
          const angle = Math.min(359.9, (node.propagationRisk / 100) * 360);
          const rad = ((angle - 90) * Math.PI) / 180;
          return (
            <g
              key={node.id}
              transform={`translate(${node.x}, ${node.y})`}
              className="cursor-pointer"
              onMouseEnter={() => setHoveredNode(node.id)}
              onMouseLeave={() => setHoveredNode(null)}
            >
              <title>{`${node.label} · ${node.propagationRisk}% risk`}</title>
              {node.compromised && (
                <circle r={NODE_RADIUS + 4} fill="none" stroke={tone('threat-critical')} strokeWidth="1.5" opacity=".5" filter="url(#topology-critical-glow)">
                  <animate attributeName="r" values={`${NODE_RADIUS + 2};${NODE_RADIUS + 8};${NODE_RADIUS + 2}`} dur="1.5s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values=".5;.1;.5" dur="1.5s" repeatCount="indefinite" />
                </circle>
              )}
              <circle
                r={NODE_RADIUS}
                fill={tone(token, node.compromised ? 0.2 : 0.12)}
                stroke={tone(token)}
                strokeWidth={node.compromised ? 2 : 1.5}
                filter={node.compromised ? 'url(#topology-critical-glow)' : isHovered ? 'url(#topology-amber-glow)' : undefined}
              />
              {angle > 0 && (
                <path
                  d={`M 0 ${-arcRadius} A ${arcRadius} ${arcRadius} 0 ${angle > 180 ? 1 : 0} 1 ${arcRadius * Math.cos(rad)} ${arcRadius * Math.sin(rad)}`}
                  fill="none"
                  stroke={tone(token)}
                  strokeWidth="2"
                  opacity=".75"
                />
              )}
              <text textAnchor="middle" dominantBaseline="middle" fontSize="16">{NODE_ICONS[node.type] ?? '◇'}</text>
              <text
                textAnchor="middle"
                y={NODE_RADIUS + 14}
                fontSize="10"
                fontFamily="IBM Plex Mono, monospace"
                fill={node.compromised ? tone('threat-critical') : tone('foreground', 0.8)}
                fontWeight={node.compromised ? 500 : 400}
                paintOrder="stroke"
                stroke={tone('background')}
                strokeWidth={3}
              >
                {isHovered ? node.label : truncateLabel(node.label)}
              </text>
              {(isHovered || node.compromised) && (
                <g transform={`translate(${NODE_RADIUS - 5},${-NODE_RADIUS + 5})`}>
                  <circle r="10" fill={tone(token)} />
                  <text textAnchor="middle" dominantBaseline="middle" fontSize="7" fontFamily="IBM Plex Mono, monospace" fill={tone('background')} fontWeight={500}>
                    {node.propagationRisk}%
                  </text>
                </g>
              )}
            </g>
          );
        })}
      </svg>
      <NetworkGraphLegend />
    </div>
  );
};

/** 3D topology (WebGL, lazy-loaded) with the SVG graph as a fallback when WebGL is unavailable. */
export const NetworkGraph = (props: NetworkGraphProps) => {
  const [failed, setFailed] = useState(false);
  const handleUnavailable = useCallback(() => setFailed(true), []);
  if (failed) return <NetworkGraph2D {...props} />;
  return (
    <Suspense fallback={<div className="ng3d-loading">Loading 3D topology…</div>}>
      <NetworkGraph3D {...props} onUnavailable={handleUnavailable} />
    </Suspense>
  );
};
