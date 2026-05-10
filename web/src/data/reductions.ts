export interface ReductionStep {
  from: string;
  to: string;
  name: string;
  theorem: string;
  paNumber: number;
  implemented: boolean;
}

export const REDUCTIONS: ReductionStep[] = [
  { from: 'OWF', to: 'PRG', name: 'HILL hard-core-bit construction', theorem: 'HILL Theorem', paNumber: 1, implemented: true },
  { from: 'PRG', to: 'PRF', name: 'GGM tree', theorem: 'GGM Theorem', paNumber: 2, implemented: true },
  { from: 'PRF', to: 'PRP', name: 'Luby-Rackoff 3-round Feistel', theorem: 'Luby-Rackoff Theorem', paNumber: 4, implemented: true },
  { from: 'PRF', to: 'MAC', name: 'PRF-MAC', theorem: 'PRF ⇒ EUF-CMA MAC', paNumber: 5, implemented: true },
  { from: 'PRP', to: 'MAC', name: 'PRP/PRF switching + MAC', theorem: 'Switching Lemma + PRF-MAC', paNumber: 5, implemented: true },
  { from: 'CRHF', to: 'HMAC', name: 'HMAC construction', theorem: 'HMAC security (Bellare 2006)', paNumber: 10, implemented: true },
  { from: 'HMAC', to: 'MAC', name: 'Direct', theorem: 'HMAC is EUF-CMA', paNumber: 10, implemented: true },
  // Backward reductions
  { from: 'PRG', to: 'OWF', name: 'PRG is a OWF', theorem: 'Immediate (expansion ⇒ non-invertible)', paNumber: 1, implemented: true },
  { from: 'PRF', to: 'PRG', name: 'G(s) = F_s(0)||F_s(1)', theorem: 'PRF ⇒ PRG', paNumber: 2, implemented: true },
  { from: 'PRP', to: 'PRF', name: 'PRP/PRF switching lemma', theorem: 'Switching Lemma', paNumber: 4, implemented: true },
  { from: 'MAC', to: 'PRF', name: 'MAC on random inputs is PRF', theorem: 'EUF-CMA ⇒ PRF on uniform', paNumber: 5, implemented: true },
  { from: 'HMAC', to: 'CRHF', name: 'Fixed-key HMAC is CRHF', theorem: 'MAC ⇒ CRHF', paNumber: 10, implemented: true },
  { from: 'MAC', to: 'HMAC', name: 'PRF-MAC in HMAC structure', theorem: 'MAC ⇒ HMAC', paNumber: 10, implemented: true },
];

export function findReductionPath(from: string, to: string): ReductionStep[] {
  // BFS to find shortest path in the reduction graph
  if (from === to) return [];

  const queue: { node: string; path: ReductionStep[] }[] = [{ node: from, path: [] }];
  const visited = new Set<string>([from]);

  while (queue.length > 0) {
    const { node, path } = queue.shift()!;
    const edges = REDUCTIONS.filter(r => r.from === node);
    for (const edge of edges) {
      if (edge.to === to) return [...path, edge];
      if (!visited.has(edge.to)) {
        visited.add(edge.to);
        queue.push({ node: edge.to, path: [...path, edge] });
      }
    }
  }
  return [];
}

export const PRIMITIVES = ['OWF', 'PRG', 'PRF', 'PRP', 'MAC', 'CRHF', 'HMAC'] as const;
export type Primitive = typeof PRIMITIVES[number];

export const PA_NUMBERS: Record<Primitive, number> = {
  OWF: 1,
  PRG: 1,
  PRF: 2,
  PRP: 4,
  MAC: 5,
  CRHF: 8,
  HMAC: 10,
};
