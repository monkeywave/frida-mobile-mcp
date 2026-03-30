import { spawn } from 'node:child_process';
import { log } from '../helpers/logger.js';

export interface FriTapCaptureOptions {
  target: string;
  deviceId?: string;
  keylogPath?: string;
  pcapPath?: string;
  mobile?: boolean;
  fullCapture?: boolean;
  antiRoot?: boolean;
}

export interface FriTapResult {
  status: 'success' | 'error';
  message: string;
  keylogPath?: string;
  pcapPath?: string;
  output: string[];
}

/**
 * Run friTap CLI for TLS traffic capture.
 * Requires `fritap` to be installed and available in PATH.
 * This is a stub for Phase 6 - full implementation will parse friTap output
 * and provide structured results.
 */
export async function captureTls(options: FriTapCaptureOptions): Promise<FriTapResult> {
  const args: string[] = [];

  if (options.mobile) args.push('-m');
  if (options.keylogPath) args.push('-k', options.keylogPath);
  if (options.pcapPath) args.push('-p', options.pcapPath);
  if (options.fullCapture) args.push('--full_capture');
  if (options.antiRoot) args.push('--anti_root');
  if (options.deviceId) args.push('-d', options.deviceId);
  args.push('-s', options.target); // spawn mode

  log('info', `Running friTap: fritap ${args.join(' ')}`);

  return new Promise((resolve, reject) => {
    const output: string[] = [];

    try {
      const proc = spawn('fritap', args, {
        stdio: ['ignore', 'pipe', 'pipe'],
      });

      proc.stdout?.on('data', (data: Buffer) => {
        const lines = data.toString().split('\n').filter(Boolean);
        output.push(...lines);
      });

      proc.stderr?.on('data', (data: Buffer) => {
        const lines = data.toString().split('\n').filter(Boolean);
        output.push(...lines);
      });

      proc.on('close', (code) => {
        resolve({
          status: code === 0 ? 'success' : 'error',
          message: code === 0 ? 'friTap capture completed' : `friTap exited with code ${code}`,
          keylogPath: options.keylogPath,
          pcapPath: options.pcapPath,
          output,
        });
      });

      proc.on('error', (err) => {
        resolve({
          status: 'error',
          message: `friTap not found or failed to start: ${err.message}. Install with: pip install friTap`,
          output: [],
        });
      });

      // Timeout after 60 seconds by default
      setTimeout(() => {
        proc.kill('SIGTERM');
      }, 60000);
    } catch (err) {
      resolve({
        status: 'error',
        message: `Failed to spawn friTap: ${err}`,
        output: [],
      });
    }
  });
}

/**
 * Check if friTap CLI is available.
 */
export async function isFriTapAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const proc = spawn('fritap', ['--help'], { stdio: 'ignore' });
      proc.on('close', () => resolve(true));
      proc.on('error', () => resolve(false));
    } catch {
      resolve(false);
    }
  });
}
