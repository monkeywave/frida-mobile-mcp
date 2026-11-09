import { describe, it, expect } from 'vitest';
import { registerPrompts } from '../src/prompts.js';

type PromptHandler = (args: Record<string, unknown>) => Promise<{ messages: Array<{ content: { text: string } }> }>;

function collectPrompts() {
  const prompts = new Map<string, { config: { argsSchema: { shape: Record<string, unknown> } }; handler: PromptHandler }>();
  const server = { registerPrompt: (name: string, config: never, handler: PromptHandler) => prompts.set(name, { config, handler }) };
  registerPrompts(server as never);
  return prompts;
}

describe('tls_traffic_audit prompt', () => {
  it('is registered with target, device and protocols args', () => {
    const prompt = collectPrompts().get('tls_traffic_audit');
    expect(prompt).toBeDefined();
    expect(Object.keys(prompt!.config.argsSchema.shape)).toEqual(['target', 'device', 'protocols']);
  });

  it('drives capture_tls with the new friTap options', async () => {
    const { handler } = collectPrompts().get('tls_traffic_audit')!;
    const text = (await handler({ target: 'com.example.app', device: 'emulator-5556', protocols: 'tls, rc4' })).messages[0].content.text;
    expect(text).toContain('capture_tls');
    expect(text).toContain('com.example.app');
    expect(text).toContain('device: "emulator-5556"');
    expect(text).toContain('["tls","rc4"]');
    for (const word of ['attribute_sdk', 'probe', 'pairip_safe', 'per_library', 'fritap_caller_stack', 'get_messages', 'stop_instrumentation', 'fritap mcp']) {
      expect(text).toContain(word);
    }
  });

  it('defaults protocols to tls', async () => {
    const { handler } = collectPrompts().get('tls_traffic_audit')!;
    const text = (await handler({ target: 'x.y' })).messages[0].content.text;
    expect(text).toContain('protocols: ["tls"]');
  });

  it('security_audit TLS step points at the new options and prompt', async () => {
    const { handler } = collectPrompts().get('security_audit')!;
    const text = (await handler({ package_name: 'x.y' })).messages[0].content.text;
    expect(text).toContain('attribute_sdk');
    expect(text).toContain('tls_traffic_audit');
  });
});
