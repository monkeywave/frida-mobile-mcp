import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { getSkillReferencePath, readSkill, readSkillReference } from '../src/resources.js';

const SKILL = 'mobile-dynamic-analysis';
const skillDir = path.resolve(__dirname, '..', 'skills', SKILL);

describe('skill references', () => {
  it('serves the reference files by basename', () => {
    expect(readSkillReference(SKILL, 'tools.md')).toContain('Frida 17.26');
    expect(readSkillReference(SKILL, 'fritap.md')).toContain('tls_traffic_audit');
  });

  it('rejects traversal, unknown files, unknown skills and non-markdown', () => {
    for (const file of ['../SKILL.md', '..%2fSKILL.md', 'a/../tools.md', '..\\SKILL.md', 'nope.md', 'tools', '']) {
      expect(getSkillReferencePath(SKILL, file), file).toBeNull();
    }
    expect(getSkillReferencePath('other-skill', 'tools.md')).toBeNull();
    expect(() => readSkillReference(SKILL, '../SKILL.md')).toThrow();
  });

  it('keeps SKILL.md within the Agent Skills size recommendation', () => {
    const body = readSkill(SKILL).replace(/^---\n[\s\S]*?\n---\n/, '');
    expect(body.split('\n').length).toBeLessThan(500);
    expect(body.length / 4).toBeLessThan(5000);
  });

  it('has valid frontmatter and resolvable relative links', () => {
    const text = readSkill(SKILL);
    const front = /^---\n([\s\S]*?)\n---/.exec(text)![1];
    expect(/^name: (.+)$/m.exec(front)![1]).toBe(SKILL);
    expect(/^description: (.+)$/m.exec(front)![1].length).toBeLessThan(1024);
    const links = [...text.matchAll(/\]\((references\/[^)]+)\)/g)].map((m) => m[1]);
    expect(links).toEqual(expect.arrayContaining(['references/tools.md', 'references/fritap.md']));
    for (const link of links) expect(existsSync(path.join(skillDir, link)), link).toBe(true);
    expect(readFileSync(path.join(skillDir, 'references/fritap.md'), 'utf8')).toContain('pairip_safe');
  });
});
