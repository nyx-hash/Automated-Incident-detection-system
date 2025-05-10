// Alert types
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Alert {
  id: string | number;
  title: string;
  sourceIp: string;
  timestamp: Date | string;
  severity: AlertSeverity;
  details?: Record<string, any> | null;
  status: 'new' | 'acknowledged' | 'resolved';
  attackType?: string | null;
}

// Incident types
export type IncidentStatus = 'open' | 'investigating' | 'mitigated';

export interface Incident {
  id: string | number;
  incidentId: string;
  title: string;
  description?: string | null;
  priority: 'P1' | 'P2' | 'P3';
  status: IncidentStatus;
  createdAt: Date | string;
  updatedAt: Date | string;
  assignedTo?: string | null;
  relatedAlerts?: any[] | null;
}

// Attack classifications
export type AttackType = 'DoS' | 'Probe' | 'R2L' | 'U2R' | 'Normal';

export interface AttackDistribution {
  type: AttackType;
  count: number;
  percentage: number;
}

// Network traffic data
export interface TrafficPoint {
  id?: number;
  timestamp: Date | string;
  value: number;
  anomalyScore?: number | null;
  packetData?: any;
  prediction?: any;
}

// ML Model types
export interface ModelFeature {
  name: string;
  importance: number;
}

export interface ModelPerformanceMetrics {
  id?: number;
  name?: string;
  version?: string;
  accuracy: number;
  precision: number;
  recall: number;
  f1Score: number;
  lastRetrained: Date | string;
  featureImportance?: any[] | null;
  isActive?: boolean | null;
}

// Network Status
export interface NetworkStatus {
  totalPackets: number;
  flaggedPackets: number;
  blockedPackets: number;
  avgResponseTime: number;
}

// Simulation types
export type SimulationStatus = 'idle' | 'running' | 'paused';

export type SimulationMode = 'real' | 'simulated' | 'attack';

export type SimulationAttackType = 'ddos' | 'port_scan' | 'brute_force' | 'data_exfiltration' | 'malware_communication';

export interface SimulationControls {
  status: SimulationStatus;
  mode: SimulationMode;
  attackType: SimulationAttackType;
  intensity: number;
  targets: string[];
}

// WebSocket message types
export interface WSMessage {
  type: 'alert' | 'traffic' | 'model' | 'incident' | 'simulation';
  data: any;
}

// KDDCup99 feature types
export interface NetworkPacket {
  duration: number;
  protocol_type: string;
  service: string;
  flag: string;
  src_bytes: number;
  dst_bytes: number;
  count: number;
  srv_count: number;
  same_srv_rate: number;
  diff_srv_rate: number;
  serror_rate: number;
  srv_serror_rate: number;
  timestamp?: number;
  prediction?: {
    attackType: AttackType;
    probability: number;
  };
}

// Process information
export interface ProcessInfo {
  pid: number;
  name: string;
  connections: number;
}
