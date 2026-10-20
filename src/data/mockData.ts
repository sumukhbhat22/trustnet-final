export type ThreatLevel = 'safe' | 'low' | 'medium' | 'high' | 'critical';
export type UserStatus = 'normal' | 'warning' | 'restricted' | 'blocked';
export type IncidentStatus = 'active' | 'investigating' | 'resolved';

export interface User {
  id: string;
  name: string;
  email: string;
  role: string;
  department: string;
  riskScore: number;
  status: UserStatus;
  lastLogin: string;
  location: string;
  device: string;
  anomalies: string[];
}

export interface Incident {
  id: string;
  timestamp: string;
  userId: string;
  userName: string;
  type: string;
  description: string;
  riskScore: number;
  threatLevel: ThreatLevel;
  status: IncidentStatus;
  response: string;
  deviation: number;
}

export interface NetworkNode {
  id: string;
  label: string;
  type: 'user' | 'app' | 'device' | 'database' | 'server';
  x: number;
  y: number;
  compromised: boolean;
  propagationRisk: number;
}

export interface NetworkEdge {
  from: string;
  to: string;
  active: boolean;
  attackPath: boolean;
}

export interface BehaviorDataPoint {
  time: string;
  normal: number;
  anomaly: number;
  riskScore: number;
}

export const initialUsers: User[] = [
  {
    id: 'u1',
    name: 'Alex Chen',
    email: 'alex.chen@corp.com',
    role: 'Senior Developer',
    department: 'Engineering',
    riskScore: 12,
    status: 'normal',
    lastLogin: '2024-01-15 09:23:11',
    location: 'San Francisco, CA',
    device: 'MacBook Pro M3',
    anomalies: [],
  },
  {
    id: 'u2',
    name: 'Sarah Mitchell',
    email: 's.mitchell@corp.com',
    role: 'Finance Manager',
    department: 'Finance',
    riskScore: 8,
    status: 'normal',
    lastLogin: '2024-01-15 08:55:44',
    location: 'New York, NY',
    device: 'Dell XPS 15',
    anomalies: [],
  },
  {
    id: 'u3',
    name: 'Marcus Johnson',
    email: 'm.johnson@corp.com',
    role: 'HR Director',
    department: 'Human Resources',
    riskScore: 15,
    status: 'normal',
    lastLogin: '2024-01-15 10:02:33',
    location: 'Chicago, IL',
    device: 'ThinkPad X1 Carbon',
    anomalies: [],
  },
  {
    id: 'u4',
    name: 'Elena Vasquez',
    email: 'e.vasquez@corp.com',
    role: 'Data Analyst',
    department: 'Analytics',
    riskScore: 22,
    status: 'normal',
    lastLogin: '2024-01-15 07:41:55',
    location: 'Austin, TX',
    device: 'Surface Pro 9',
    anomalies: [],
  },
  {
    id: 'u5',
    name: 'David Park',
    email: 'd.park@corp.com',
    role: 'System Administrator',
    department: 'IT',
    riskScore: 18,
    status: 'normal',
    lastLogin: '2024-01-15 06:30:00',
    location: 'Seattle, WA',
    device: 'Mac Mini M2',
    anomalies: [],
  },
];

export const initialIncidents: Incident[] = [
  {
    id: 'INC-001',
    timestamp: '2024-01-14 23:41:02',
    userId: 'u2',
    userName: 'Sarah Mitchell',
    type: 'Off-Hours Access',
    description: 'Login attempt detected outside normal working hours (11:41 PM)',
    riskScore: 45,
    threatLevel: 'medium',
    status: 'resolved',
    response: 'MFA challenge issued — verified successfully',
    deviation: 67,
  },
  {
    id: 'INC-002',
    timestamp: '2024-01-13 14:22:18',
    userId: 'u4',
    userName: 'Elena Vasquez',
    type: 'Unusual Data Volume',
    description: 'Database query exported 3.2x normal data volume in one session',
    riskScore: 62,
    threatLevel: 'high',
    status: 'investigating',
    response: 'Session flagged — security review initiated',
    deviation: 82,
  },
  {
    id: 'INC-003',
    timestamp: '2024-01-12 09:15:44',
    userId: 'u1',
    userName: 'Alex Chen',
    type: 'New Device Login',
    description: 'Authentication from unrecognized device fingerprint',
    riskScore: 38,
    threatLevel: 'medium',
    status: 'resolved',
    response: 'Device added to trusted list after verification',
    deviation: 55,
  },
];

export const networkNodes: NetworkNode[] = [
  { id: 'n1', label: 'Alex Chen', type: 'user', x: 200, y: 150, compromised: false, propagationRisk: 15 },
  { id: 'n2', label: 'Sarah Mitchell', type: 'user', x: 500, y: 100, compromised: false, propagationRisk: 8 },
  { id: 'n3', label: 'Marcus Johnson', type: 'user', x: 750, y: 180, compromised: false, propagationRisk: 12 },
  { id: 'n4', label: 'Web App', type: 'app', x: 350, y: 280, compromised: false, propagationRisk: 30 },
  { id: 'n5', label: 'Finance DB', type: 'database', x: 600, y: 300, compromised: false, propagationRisk: 45 },
  { id: 'n6', label: 'HR Portal', type: 'app', x: 750, y: 350, compromised: false, propagationRisk: 25 },
  { id: 'n7', label: 'Core Server', type: 'server', x: 450, y: 420, compromised: false, propagationRisk: 60 },
  { id: 'n8', label: 'Dev Laptop', type: 'device', x: 150, y: 330, compromised: false, propagationRisk: 20 },
  { id: 'n9', label: 'Analytics DB', type: 'database', x: 300, y: 430, compromised: false, propagationRisk: 40 },
  { id: 'n10', label: 'Email Server', type: 'server', x: 650, y: 460, compromised: false, propagationRisk: 35 },
];

export const networkEdges: NetworkEdge[] = [
  { from: 'n1', to: 'n4', active: true, attackPath: false },
  { from: 'n1', to: 'n8', active: true, attackPath: false },
  { from: 'n2', to: 'n5', active: true, attackPath: false },
  { from: 'n2', to: 'n4', active: true, attackPath: false },
  { from: 'n3', to: 'n6', active: true, attackPath: false },
  { from: 'n4', to: 'n7', active: true, attackPath: false },
  { from: 'n4', to: 'n9', active: true, attackPath: false },
  { from: 'n5', to: 'n7', active: true, attackPath: false },
  { from: 'n6', to: 'n10', active: true, attackPath: false },
  { from: 'n7', to: 'n9', active: true, attackPath: false },
  { from: 'n7', to: 'n10', active: true, attackPath: false },
  { from: 'n8', to: 'n9', active: true, attackPath: false },
];

export const generateBehaviorData = (): BehaviorDataPoint[] => {
  const hours = ['00:00', '02:00', '04:00', '06:00', '08:00', '10:00', '12:00', '14:00', '16:00', '18:00', '20:00', '22:00'];
  return hours.map((time, i) => ({
    time,
    normal: Math.max(0, 20 + Math.sin(i * 0.8) * 15 + (i > 3 && i < 9 ? 40 : 0)),
    anomaly: Math.random() * 5,
    riskScore: Math.max(5, 10 + Math.random() * 20 + (i > 3 && i < 9 ? 5 : 0)),
  }));
};

export const generateRiskTrendData = () => {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  return days.map((day) => ({
    day,
    riskScore: Math.floor(15 + Math.random() * 25),
    incidents: Math.floor(Math.random() * 4),
    anomalies: Math.floor(Math.random() * 8),
  }));
};
