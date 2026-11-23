// ---------------------------------------------------------------------------
// Louvain community detection on a small weighted undirected graph (the memory
// map's similarity graph: a few thousand nodes, about ten edges each).
//
// Deterministic: nodes are visited in index order and ties keep the lower
// community id, so the same graph always gives the same communities. That
// matters here because the dashboard draws the communities as topics, and a
// person must not see their topics reshuffle when nothing changed.
//
// `resolution` > 1 gives more, smaller communities; < 1 fewer, larger ones.
// ---------------------------------------------------------------------------

export interface WeightedGraph {
  /** Number of nodes, ids 0..n-1. */
  n: number;
  /** Undirected edges [a, b, weight]; each pair once. Weights must be > 0. */
  edges: Array<[number, number, number]>;
}

interface Level {
  n: number;
  /** adjacency: for each node, neighbour ids and weights (self loops included once, counted twice in degree) */
  nbr: number[][];
  w: number[][];
  self: Float64Array;
  degree: Float64Array;
}

function levelOf(n: number, edges: Array<[number, number, number]>): Level {
  const nbr: number[][] = Array.from({ length: n }, () => []);
  const w: number[][] = Array.from({ length: n }, () => []);
  const self = new Float64Array(n);
  const degree = new Float64Array(n);
  for (const [a, b, x] of edges) {
    if (!(x > 0)) continue;
    if (a === b) {
      self[a] += x;
      degree[a] += 2 * x;
      continue;
    }
    nbr[a].push(b); w[a].push(x);
    nbr[b].push(a); w[b].push(x);
    degree[a] += x;
    degree[b] += x;
  }
  return { n, nbr, w, self, degree };
}

/** One pass of local moves. Returns the community of each node, renumbered 0..k-1, and whether anything moved. */
function moveNodes(level: Level, m2: number, resolution: number): { comm: Int32Array; moved: boolean } {
  const { n, nbr, w, degree } = level;
  const comm = new Int32Array(n);
  const tot = new Float64Array(n);
  for (let i = 0; i < n; i++) { comm[i] = i; tot[i] = degree[i]; }
  const linkTo = new Float64Array(n);
  const touched: number[] = [];
  let moved = false;
  for (let pass = 0; pass < 50; pass++) {
    let changes = 0;
    for (let i = 0; i < n; i++) {
      const ki = degree[i];
      if (ki === 0) continue;
      const own = comm[i];
      // Weight from i to each neighbouring community.
      for (let e = 0; e < nbr[i].length; e++) {
        const c = comm[nbr[i][e]];
        if (linkTo[c] === 0) touched.push(c);
        linkTo[c] += w[i][e];
      }
      tot[own] -= ki;
      let best = own;
      let bestGain = linkTo[own] - (resolution * tot[own] * ki) / m2;
      for (const c of touched) {
        const gain = linkTo[c] - (resolution * tot[c] * ki) / m2;
        if (gain > bestGain + 1e-12 || (Math.abs(gain - bestGain) <= 1e-12 && c < best)) {
          best = c;
          bestGain = gain;
        }
      }
      tot[best] += ki;
      if (best !== own) {
        comm[i] = best;
        changes++;
        moved = true;
      }
      for (const c of touched) linkTo[c] = 0;
      linkTo[own] = 0;
      touched.length = 0;
    }
    if (changes === 0) break;
  }
  // Renumber in order of first appearance, so the numbering does not depend on which node id a community kept.
  const remap = new Map<number, number>();
  for (let i = 0; i < n; i++) {
    if (!remap.has(comm[i])) remap.set(comm[i], remap.size);
    comm[i] = remap.get(comm[i])!;
  }
  return { comm, moved };
}

function aggregate(level: Level, comm: Int32Array): Level {
  const k = Math.max(-1, ...comm) + 1;
  const acc = new Map<number, number>();
  const key = (a: number, b: number) => (a < b ? a * k + b : b * k + a);
  for (let i = 0; i < level.n; i++) {
    if (level.self[i] > 0) acc.set(key(comm[i], comm[i]), (acc.get(key(comm[i], comm[i])) ?? 0) + level.self[i]);
    for (let e = 0; e < level.nbr[i].length; e++) {
      const j = level.nbr[i][e];
      if (j < i) continue; // each undirected edge once
      const kk = key(comm[i], comm[j]);
      acc.set(kk, (acc.get(kk) ?? 0) + level.w[i][e]);
    }
  }
  const edges: Array<[number, number, number]> = [];
  for (const [kk, x] of acc) edges.push([Math.floor(kk / k), kk % k, x]);
  return levelOf(k, edges);
}

/**
 * Communities of `graph`: an array giving each node's community, numbered 0..k-1 by first appearance.
 * A node with no edges is a community of its own.
 */
export function louvain(graph: WeightedGraph, resolution = 1): Int32Array {
  let level = levelOf(graph.n, graph.edges);
  let m2 = 0;
  for (let i = 0; i < level.n; i++) m2 += level.degree[i];
  const result = new Int32Array(graph.n);
  for (let i = 0; i < graph.n; i++) result[i] = i;
  if (m2 === 0) return result;
  for (let round = 0; round < 20; round++) {
    const { comm, moved } = moveNodes(level, m2, resolution);
    if (!moved) break;
    for (let i = 0; i < graph.n; i++) result[i] = comm[result[i]];
    level = aggregate(level, comm);
  }
  // Final renumbering by first appearance over the original nodes.
  const remap = new Map<number, number>();
  for (let i = 0; i < graph.n; i++) {
    if (!remap.has(result[i])) remap.set(result[i], remap.size);
    result[i] = remap.get(result[i])!;
  }
  return result;
}
