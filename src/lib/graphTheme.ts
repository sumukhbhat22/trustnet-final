export const tone = (token: string, alpha?: number) => `hsl(var(--${token})${alpha === undefined ? '' : ` / ${alpha}`})`;

export const NODE_TOKENS: Record<string, string> = {
  user: 'primary',
  device: 'foreground',
  app: 'threat-low',
  server: 'threat-high',
  database: 'threat-safe',
  asset: 'threat-safe',
};

export const LEGEND: Array<[string, string]> = [
  ['primary', 'User'],
  ['foreground', 'Device'],
  ['threat-low', 'App'],
  ['threat-high', 'Server'],
  ['threat-safe', 'Database'],
  ['threat-critical', 'Compromised'],
];

const LABEL_MAX = 16;
export const truncateLabel = (label: string) => (label.length > LABEL_MAX ? `${label.slice(0, LABEL_MAX - 1)}…` : label);
