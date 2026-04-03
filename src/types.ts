import type frida from 'frida';

// Session entry stored in state
export interface SessionEntry {
  id: string;               // UUID
  session: frida.Session;
  pid: number;
  deviceId: string;
  target: string;           // app bundle ID or process name
  platform: 'android' | 'ios' | 'linux' | 'macos' | 'windows' | 'unknown';
  scripts: Map<string, ScriptEntry>;
  createdAt: number;
}

export interface ScriptEntry {
  id: string;               // UUID
  script: frida.Script;
  messages: MessageEntry[];
  name?: string;
  persistent: boolean;      // whether script stays loaded
  createdAt: number;
}

export interface MessageEntry {
  index: number;
  timestamp: number;
  type: string;
  payload: unknown;
  data: Buffer | null;
}

export interface HookEntry {
  id: string;
  scriptId: string;
  sessionId: string;
  target: string;
  type: 'native' | 'java' | 'objc';
  invocations: HookInvocation[];
  status: 'active' | 'completed' | 'error';
  createdAt: number;
}

export interface HookInvocation {
  timestamp: number;
  threadId: number;
  args: unknown[];
  retval: unknown;
  backtrace: string[] | null;
}

export interface TraceEntry {
  id: string;
  scriptId: string;
  sessionId: string;
  targets: string[];
  callCount: number;
  startedAt: number;
}

// Tool return value structure
export interface ToolResult<T = unknown> {
  result: T;
  session_context: SessionContext;
  suggested_next: SuggestedAction[];
}

export interface SessionContext {
  device: string | null;
  platform: string | null;
  active_sessions: Array<{
    id: string;
    target: string;
    pid: number;
  }>;
  active_hooks: number;
  active_scripts: number;
}

export interface SuggestedAction {
  tool: string;
  args?: Record<string, unknown>;
  reason: string;
  condition?: string;
  priority?: 'required' | 'recommended' | 'optional';
}

// Error types
export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    recovery_actions: RecoveryAction[];
    context?: Record<string, unknown>;
  };
}

export interface RecoveryAction {
  tool?: string;
  args?: Record<string, unknown>;
  action?: string;
  reason?: string;
  message?: string;
}

export type ScriptCategory = 'bypass' | 'enumeration' | 'security' | 'network' | 'crypto' | 'filesystem' | 'detection';

// Script template
export interface ScriptTemplate {
  name: string;
  description: string;
  platforms: Array<'android' | 'ios'>;
  category: ScriptCategory;
  riskTier: 1 | 2 | 3;
  options?: Record<string, ScriptOption>;
  generate: (options: Record<string, unknown>, context?: PlatformContext) => string;
}

export interface ScriptOption {
  type: 'string' | 'boolean' | 'number';
  description: string;
  default?: unknown;
  required?: boolean;
}

export interface PlatformContext {
  platform: 'android' | 'ios' | 'unknown';
  apiLevel?: number;
  osVersion?: string;
  arch?: string;
}

// Device info
export interface DeviceInfo {
  id: string;
  name: string;
  type: string;
  platform?: string;
  os?: string;
  arch?: string;
}

// Config types
export interface FridaMcpConfig {
  allowCustomScripts: boolean;
  memoryWriteEnabled: boolean;
  allowedDevices: string[];
  maxSessions: number;
  sessionTimeoutMinutes: number;
  maxMessageBuffer: number;
  auditLogPath: string;
  mobileMcp: MobileMcpConfig;
  rateLimits: RateLimitConfig;
}

export interface MobileMcpConfig {
  enabled: boolean;
  command: string;
  args: string[];
}

export interface RateLimitConfig {
  scriptsPerMinute: number;
  memoryReadsPerMinute: number;
  sessionsPerMinute: number;
}
