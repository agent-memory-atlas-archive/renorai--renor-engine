import { describe, it, expect } from 'vitest';
import { chunkNote } from '../../src/indexer/chunker';
import { ParsedNote } from '../../src/indexer/parser';

const note = (body: string): ParsedNote => ({
  path: '/v/t.md',
  title: 'T',
  frontmatter: {},
  body,
  wikilinks: [],
});

describe('chunkNote', () => {
  it('returns at least one chunk', () => {
    expect(chunkNote(note('text')).length).toBeGreaterThanOrEqual(1);
  });

  it('splits by headings and tracks heading path', () => {
    const chunks = chunkNote(note('# S1\n\nA.\n\n## S1.1\n\nB.\n\n# S2\n\nC.'));
    expect(chunks.length).toBe(3);
    expect(chunks[0].headingPath).toBe('S1');
    expect(chunks[1].headingPath).toBe('S1 > S1.1');
    expect(chunks[2].headingPath).toBe('S2');
  });

  it('respects max token limit', () => {
    const long = ('word '.repeat(100) + '\n\n').repeat(6);
    const chunks = chunkNote(note(long), { maxTokens: 400 });
    expect(chunks.every(c => c.tokenCount <= 450)).toBe(true);
  });

  it('sets startLine and endLine', () => {
    const chunks = chunkNote(note('# A\n\nText A.\n\n# B\n\nText B.'));
    chunks.forEach(c => {
      expect(c.startLine).toBeGreaterThanOrEqual(0);
      expect(c.endLine).toBeGreaterThan(c.startLine);
    });
  });

  it('creates overlapping chunks when overlapTokens is set', () => {
    const long = ('word '.repeat(100) + '\n\n').repeat(6);
    const chunks = chunkNote(note(long), { maxTokens: 400, overlapTokens: 50 });
    // Adjacent chunks should share some text
    if (chunks.length >= 2) {
      const end1 = chunks[0].text;
      const start2 = chunks[1].text;
      // The overlap means the end of chunk 1 text should appear at start of chunk 2
      const lastPara1 = end1.split('\n\n').pop()!;
      expect(start2).toContain(lastPara1);
    }
  });
});

describe('chunkNote with Windows line endings', () => {
  const para = (n: number) => `Paragraph ${n}: ` + 'word '.repeat(60).trim();
  const lf = [1, 2, 3, 4, 5, 6].map(para).join('\n\n');
  const norm = (s: string) => s.replace(/\r/g, '');
  const bodies: Record<string, string> = {
    plain: lf,
    heading: `# Title\n\n${lf}`,
    'many entries': `# Day\n\n${lf}\n\n## Later\n\n${lf}`,
  };
  for (const [name, body] of Object.entries(bodies)) {
    it(`CRLF gives the same chunks as LF: ${name}`, () => {
      const a = chunkNote(note(body), { maxTokens: 150 });
      const b = chunkNote(note(body.replace(/\n/g, '\r\n')), { maxTokens: 150 });
      expect(a.length).toBeGreaterThan(1);
      expect(b.length).toBe(a.length);
      expect(b.map(c => norm(c.text))).toEqual(a.map(c => c.text));
      expect(b.map(c => [c.startLine, c.endLine])).toEqual(a.map(c => [c.startLine, c.endLine]));
    });
  }

  it('does not crash on a lone CR or mixed endings', () => {
    const mixed = [1, 2, 3, 4].map(para).join('\r\n\n');
    expect(chunkNote(note(mixed), { maxTokens: 150 }).length).toBeGreaterThan(1);
    expect(() => chunkNote(note(lf.replace(/\n/g, '\r')), { maxTokens: 150 })).not.toThrow();
  });
});
