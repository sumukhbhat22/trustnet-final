import { LEGEND, tone } from '@/lib/graphTheme';

export const NetworkGraphLegend = () => (
  <div className="network-graph-legend" aria-label="Topology legend">
    {LEGEND.map(([token, label]) => (
      <span key={label}><i style={{ backgroundColor: tone(token) }} />{label}</span>
    ))}
  </div>
);
