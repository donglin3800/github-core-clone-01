// github-core-clone: a single-process GitHub-compatible git forge.
//
// One file, Node 22 stdlib only, no dependencies, no git binary, no network
// beyond the trial environment. In-memory store, fully deterministic: no wall
// clock and no randomness anywhere in stored state or responses, so a replay
// leaves byte-identical state.
//
// Surfaces:
//   GET  /healthz                          (no auth)
//   Git smart HTTP  /{owner}/{repo}.git    (upload-pack v2 + v0, receive-pack v0)
//   REST v3         /api/v3/...            (bearer token)
//   GraphQL         /api/graphql           (bearer token)
//   MCP             /mcp                   (JSON-RPC 2.0 Streamable HTTP, bearer token)
//
// Lifecycle: bind an ephemeral port, POST {"port": N} to $MAKEFUN_ENV_URL/register,
// poll GET $MAKEFUN_ENV_URL/done and exit 0 on {"done": true}. With no
// MAKEFUN_ENV_URL set, serve forever (local test mode).
import http from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

const ZERO_OID = '0000000000000000000000000000000000000000';
const VIEWER_LOGIN = 'adaiversen';
const VIEWER_ID = 1000;
const VIEWER_NAME = 'ada iversen';
const VIEWER_EMAIL = 'adaiversen@example.invalid';
const AGENT = 'github-core-clone/1.0.0';
const EPOCH = 1700000000;
const FIXED_ISO = '2025-01-01T00:00:00Z';
const IDENTITY = 'adaiversen <adaiversen@example.invalid>';
const EMPTY_TREE_OID = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';

type GitObjectType = 'commit' | 'tree' | 'blob' | 'tag';

interface GitObject {
  type: GitObjectType;
  data: Buffer;
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

interface CommitInfo {
  tree: string;
  parents: string[];
}

interface TagInfo {
  object: string;
  type: string;
}

// ------------------------------------------------------------------ hashing

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function hashObject(type: GitObjectType, data: Buffer): string {
  const head = Buffer.from(type + ' ' + data.length + '\0', 'utf8');
  const hash = createHash('sha1');
  hash.update(head);
  hash.update(data);
  return hash.digest('hex');
}

function b64uEncode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64url');
}

function b64uDecode(text: string): string {
  return Buffer.from(text, 'base64url').toString('utf8');
}

// ------------------------------------------------------------------ pkt-lines

function pktLine(payload: string | Buffer): Buffer {
  const data = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const head = Buffer.allocUnsafe(4);
  head.write((data.length + 4).toString(16).padStart(4, '0'), 0, 4, 'ascii');
  return Buffer.concat([head, data]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

interface Pkt {
  kind: 'data' | 'flush' | 'delim' | 'response-end';
  payload: Buffer | null;
}

/** Decode pkt-lines from the start of `buf` until the first flush (or the end). */
function decodePktLines(buf: Buffer): { packets: Pkt[]; rest: number } {
  const packets: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.toString('ascii', off, off + 4), 16);
    if (Number.isNaN(len) || len < 0) throw new Error('bad pkt-line header');
    if (len === 0) {
      packets.push({ kind: 'flush', payload: null });
      off += 4;
      break;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: null });
      off += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'response-end', payload: null });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return { packets, rest: off };
}

function pktLinesToStrings(packets: Pkt[]): string[] {
  const out: string[] = [];
  for (const p of packets) {
    if (p.kind === 'data' && p.payload !== null) out.push(p.payload.toString('utf8'));
  }
  return out;
}

/** Decode every pkt-line in `buf` (flush packets do not stop the scan). */
function decodeAllPktLines(buf: Buffer): Pkt[] {
  const packets: Pkt[] = [];
  let off = 0;
  while (off + 4 <= buf.length) {
    const len = parseInt(buf.toString('ascii', off, off + 4), 16);
    if (Number.isNaN(len) || len < 0) throw new Error('bad pkt-line header');
    if (len === 0) {
      packets.push({ kind: 'flush', payload: null });
      off += 4;
      continue;
    }
    if (len === 1) {
      packets.push({ kind: 'delim', payload: null });
      off += 4;
      continue;
    }
    if (len === 2) {
      packets.push({ kind: 'response-end', payload: null });
      off += 4;
      continue;
    }
    if (len < 4 || off + len > buf.length) throw new Error('bad pkt-line length');
    packets.push({ kind: 'data', payload: buf.subarray(off + 4, off + len) });
    off += len;
  }
  return packets;
}

// ------------------------------------------------------------------ packfiles

const TYPE_CODE: Record<GitObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const CODE_TYPE: Record<number, GitObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function writePackObjectHeader(type: GitObjectType, size: number): Buffer {
  const code = TYPE_CODE[type];
  const bytes: number[] = [];
  let remaining = size;
  let first = (code << 4) | (remaining & 0x0f);
  remaining = Math.floor(remaining / 16);
  while (remaining > 0) {
    bytes.push(first | 0x80);
    first = remaining & 0x7f;
    remaining = Math.floor(remaining / 128);
  }
  bytes.push(first);
  return Buffer.from(bytes);
}

/** Build a packfile from plain objects (no deltas), in the given order. */
function writePack(objects: GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const head = Buffer.allocUnsafe(12);
  head.write('PACK', 0, 4, 'ascii');
  head.writeUInt32BE(2, 4);
  head.writeUInt32BE(objects.length, 8);
  parts.push(head);
  for (const object of objects) {
    parts.push(writePackObjectHeader(object.type, object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

/** Apply a git delta instruction stream to a base object's bytes. */
function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let off = 0;
  const readSize = (): number => {
    let value = 0;
    let shift = 0;
    for (;;) {
      if (off >= delta.length) throw new Error('delta size varint truncated');
      const byte = delta[off++];
      value += (byte & 0x7f) * 2 ** shift;
      shift += 7;
      if (!(byte & 0x80)) break;
    }
    return value;
  };
  const sourceSize = readSize();
  const targetSize = readSize();
  if (sourceSize !== base.length) throw new Error('delta base size mismatch');
  const out = Buffer.allocUnsafe(targetSize);
  let written = 0;
  while (off < delta.length) {
    const op = delta[off++];
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      let shift = 0;
      for (let bit = 0; bit < 4; bit += 1) {
        if (op & (1 << bit)) {
          if (off >= delta.length) throw new Error('delta copy offset truncated');
          copyOffset += delta[off++] * 2 ** shift;
        }
        shift += 8;
      }
      shift = 0;
      for (let bit = 4; bit < 7; bit += 1) {
        if (op & (1 << bit)) {
          if (off >= delta.length) throw new Error('delta copy size truncated');
          copySize += delta[off++] * 2 ** shift;
        }
        shift += 8;
      }
      if (copySize === 0) copySize = 0x10000;
      if (copyOffset + copySize > base.length) throw new Error('delta copy out of range');
      if (written + copySize > targetSize) throw new Error('delta writes past target');
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op !== 0) {
      const literal = op & 0x7f;
      if (off + literal > delta.length) throw new Error('delta insert truncated');
      if (written + literal > targetSize) throw new Error('delta writes past target');
      delta.copy(out, written, off, off + literal);
      off += literal;
      written += literal;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize) throw new Error('delta size mismatch');
  return out;
}

interface PackEntry {
  offset: number;
  typeCode: number;
  size: number;
  data: Buffer;
  baseOffset: number;
  baseOid: string;
}

/** Read a packfile into a map of oid -> object, resolving OFS/REF deltas. */
function readPack(buf: Buffer): Map<string, GitObject> {
  if (buf.length < 32 || buf.toString('ascii', 0, 4) !== 'PACK') throw new Error('not a packfile');
  const count = buf.readUInt32BE(8);
  const trailer = buf.subarray(buf.length - 20).toString('hex');
  const expected = sha1Hex(buf.subarray(0, buf.length - 20));
  if (trailer !== expected) throw new Error('pack checksum mismatch');
  let off = 12;
  const entries: PackEntry[] = [];
  for (let i = 0; i < count; i += 1) {
    const start = off;
    let byte = buf[off++];
    const typeCode = (byte >> 4) & 7;
    let size = byte & 0x0f;
    let shift = 4;
    while (byte & 0x80) {
      if (off >= buf.length) throw new Error('pack size varint truncated');
      byte = buf[off++];
      size += (byte & 0x7f) * 2 ** shift;
      shift += 7;
    }
    let baseOffset = -1;
    let baseOid = '';
    if (typeCode === 6) {
      byte = buf[off++];
      let value = byte & 0x7f;
      while (byte & 0x80) {
        if (off >= buf.length) throw new Error('ofs-delta offset truncated');
        byte = buf[off++];
        value = ((value + 1) << 7) + (byte & 0x7f);
      }
      baseOffset = start - value;
    } else if (typeCode === 7) {
      baseOid = buf.subarray(off, off + 20).toString('hex');
      off += 20;
    } else if (CODE_TYPE[typeCode] === undefined) {
      throw new Error('unknown pack object type ' + typeCode);
    }
    const inflated = inflateSync(buf.subarray(off), { info: true }) as unknown as {
      buffer: Buffer;
      engine: { bytesWritten: number };
    };
    const data: Buffer = inflated.buffer;
    if (data.length !== size) throw new Error('inflated size mismatch');
    off += inflated.engine.bytesWritten;
    entries.push({ offset: start, typeCode, size, data, baseOffset, baseOid });
  }
  const byOffset = new Map<number, GitObject & { oid: string }>();
  const out = new Map<string, GitObject>();
  const resolve = (index: number): GitObject & { oid: string } => {
    const entry = entries[index];
    if (entry === undefined) throw new Error('pack entry out of range');
    const cached = byOffset.get(entry.offset);
    if (cached !== undefined) return cached;
    let resolved: GitObject & { oid: string };
    if (entry.typeCode === 6 || entry.typeCode === 7) {
      let base: GitObject & { oid: string } | undefined;
      if (entry.typeCode === 6) {
        const baseIndex = entries.findIndex((e) => e.offset === entry.baseOffset);
        if (baseIndex < 0) throw new Error('ofs-delta base not in pack');
        base = resolve(baseIndex);
      } else {
        const existing = out.get(entry.baseOid);
        if (existing === undefined) throw new Error('ref-delta base not in pack');
        base = { ...existing, oid: entry.baseOid };
      }
      const data = applyDelta(base.data, entry.data);
      const oid = hashObject(base.type, data);
      resolved = { type: base.type, data, oid };
    } else {
      const type = CODE_TYPE[entry.typeCode] as GitObjectType;
      const oid = hashObject(type, entry.data);
      resolved = { type, data: entry.data, oid };
    }
    byOffset.set(entry.offset, resolved);
    out.set(resolved.oid, { type: resolved.type, data: resolved.data });
    return resolved;
  };
  for (let i = 0; i < entries.length; i += 1) resolve(i);
  return out;
}

// ------------------------------------------------------------------ object model

function compareTreeEntries(a: TreeEntry, b: TreeEntry): number {
  const left = Buffer.from(a.mode === '40000' ? a.name + '/' : a.name, 'utf8');
  const right = Buffer.from(b.mode === '40000' ? b.name + '/' : b.name, 'utf8');
  return Buffer.compare(left, right);
}

/** Build a tree object's bytes from entries, sorted the way git sorts them. */
function buildTreeBytes(entries: TreeEntry[]): Buffer {
  const sorted = [...entries].sort(compareTreeEntries);
  const parts: Buffer[] = [];
  for (const entry of sorted) {
    parts.push(Buffer.from(entry.mode + ' ' + entry.name + '\0', 'utf8'));
    parts.push(Buffer.from(entry.oid, 'hex'));
  }
  return Buffer.concat(parts);
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let off = 0;
  while (off < data.length) {
    const space = data.indexOf(0x20, off);
    if (space < 0) throw new Error('bad tree entry');
    const nul = data.indexOf(0x00, space);
    if (nul < 0 || nul + 21 > data.length) throw new Error('bad tree entry');
    const mode = data.toString('utf8', off, space);
    const name = data.toString('utf8', space + 1, nul);
    const oid = data.subarray(nul + 1, nul + 21).toString('hex');
    entries.push({ mode, name, oid });
    off = nul + 21;
  }
  return entries;
}

function parseCommit(data: Buffer): CommitInfo {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  let tree = '';
  const parents: string[] = [];
  const headerText = data.subarray(0, headerEnd).toString('utf8');
  for (const line of headerText.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5);
    else if (line.startsWith('parent ')) parents.push(line.slice(7));
  }
  if (tree === '') throw new Error('commit has no tree');
  return { tree, parents };
}

function parseTag(data: Buffer): TagInfo {
  const blank = data.indexOf('\n\n');
  const headerEnd = blank < 0 ? data.length : blank;
  const headers = new Map<string, string>();
  for (const line of data.subarray(0, headerEnd).toString('utf8').split('\n')) {
    const space = line.indexOf(' ');
    if (space > 0) headers.set(line.slice(0, space), line.slice(space + 1));
  }
  return { object: headers.get('object') ?? '', type: headers.get('type') ?? '' };
}

/** Build a commit object's bytes. Message is stored exactly as given. */
function buildCommitBytes(tree: string, parents: string[], message: string, timestamp: number): Buffer {
  const lines = ['tree ' + tree];
  for (const parent of parents) lines.push('parent ' + parent);
  lines.push('author ' + IDENTITY + ' ' + timestamp + ' +0000');
  lines.push('committer ' + IDENTITY + ' ' + timestamp + ' +0000');
  lines.push('');
  return Buffer.from(lines.join('\n') + '\n' + message, 'utf8');
}

function countLines(text: string): number {
  if (text === '') return 0;
  const parts = text.split('\n');
  if (parts.length > 0 && parts[parts.length - 1] === '') parts.pop();
  return parts.length;
}

/** Line diff by common prefix/suffix: additions/deletions between two texts. */
function lineDiff(oldText: string, newText: string): { add: number; del: number } {
  const oldLines = oldText === '' ? [] : oldText.split('\n');
  const newLines = newText === '' ? [] : newText.split('\n');
  if (oldLines.length > 0 && oldLines[oldLines.length - 1] === '') oldLines.pop();
  if (newLines.length > 0 && newLines[newLines.length - 1] === '') newLines.pop();
  let prefix = 0;
  while (
    prefix < oldLines.length &&
    prefix < newLines.length &&
    oldLines[prefix] === newLines[prefix]
  ) {
    prefix += 1;
  }
  let suffix = 0;
  while (
    suffix < oldLines.length - prefix &&
    suffix < newLines.length - prefix &&
    oldLines[oldLines.length - 1 - suffix] === newLines[newLines.length - 1 - suffix]
  ) {
    suffix += 1;
  }
  return {
    add: newLines.length - prefix - suffix,
    del: oldLines.length - prefix - suffix,
  };
}

// ------------------------------------------------------------------ store model

interface Label {
  name: string;
  color: string;
}

interface Comment {
  id: number;
  body: string;
}

interface Issue {
  id: number;
  number: number;
  repoId: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  comments: Comment[];
  /** Serialized JSON for the single-issue fast path; null when stale. */
  _json: string | null;
}

interface Pull {
  id: number;
  number: number;
  repoId: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string;
  mergeCommitSha: string;
  headRef: string;
  baseRef: string;
  headSha: string;
  baseSha: string;
}

interface Repo {
  id: number;
  name: string;
  owner: string;
  private: boolean;
  description: string;
  defaultBranch: string;
  refs: Map<string, string>;
  objects: Map<string, GitObject>;
  commitCache: Map<string, CommitInfo>;
  treeCache: Map<string, TreeEntry[]>;
  labels: Map<string, Label>;
  issues: Map<number, Issue>;
  pulls: Map<number, Pull>;
  nextNumber: number;
  commitSeq: number;
  /** Response caches, all derived from objects+refs; cleared by bumpRepo. */
  fetchCache: Map<string, Buffer>;
  lsRefsCache: Map<string, Buffer>;
  v0AdvCache: Map<string, Buffer>;
}

const reposByName = new Map<string, Repo>();
const reposById = new Map<number, Repo>();
let repoSeq = 0;
let entitySeq = 0;
let reqSeq = 0;

function createRepo(name: string, isPrivate: boolean, description: string): Repo {
  const repo: Repo = {
    id: ++repoSeq,
    name,
    owner: VIEWER_LOGIN,
    private: isPrivate,
    description,
    defaultBranch: 'main',
    refs: new Map(),
    objects: new Map(),
    commitCache: new Map(),
    treeCache: new Map(),
    labels: new Map(),
    issues: new Map(),
    pulls: new Map(),
    nextNumber: 1,
    commitSeq: 0,
    fetchCache: new Map(),
    lsRefsCache: new Map(),
    v0AdvCache: new Map(),
  };
  reposByName.set(name, repo);
  reposById.set(repo.id, repo);
  return repo;
}

function getRepo(owner: string, name: string): Repo | undefined {
  if (owner !== VIEWER_LOGIN) return undefined;
  return reposByName.get(name);
}

/** Drop a repo's derived response caches after its objects or refs change. */
function bumpRepo(repo: Repo): void {
  repo.fetchCache.clear();
  repo.lsRefsCache.clear();
  repo.v0AdvCache.clear();
}

function getCommit(repo: Repo, oid: string): CommitInfo | undefined {
  const cached = repo.commitCache.get(oid);
  if (cached !== undefined) return cached;
  const obj = repo.objects.get(oid);
  if (obj === undefined || obj.type !== 'commit') return undefined;
  const parsed = parseCommit(obj.data);
  repo.commitCache.set(oid, parsed);
  return parsed;
}

function getTree(repo: Repo, oid: string): TreeEntry[] {
  const cached = repo.treeCache.get(oid);
  if (cached !== undefined) return cached;
  const obj = repo.objects.get(oid);
  if (obj === undefined || obj.type !== 'tree') return [];
  const parsed = parseTree(obj.data);
  repo.treeCache.set(oid, parsed);
  return parsed;
}

/** Peel a tag object to its target commit oid (or the oid itself when not a tag). */
function peelToCommit(repo: Repo, oid: string): string {
  const obj = repo.objects.get(oid);
  if (obj !== undefined && obj.type === 'tag') {
    const target = parseTag(obj.data).object;
    return peelToCommit(repo, target);
  }
  return oid;
}

/** True when `ancestor` is reachable from `descendant` following parents. */
function isAncestor(repo: Repo, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  const stack: string[] = [descendant];
  const seen = new Set<string>();
  while (stack.length > 0) {
    const cur = stack.pop() as string;
    if (cur === ancestor) return true;
    if (seen.has(cur)) continue;
    seen.add(cur);
    const commit = getCommit(repo, cur);
    if (commit === undefined) continue;
    for (const parent of commit.parents) stack.push(parent);
  }
  return false;
}

/** Every object reachable from `roots` (commits, trees, blobs, tags). */
function collectAll(repo: Repo, roots: Iterable<string>, out: Set<string>): void {
  const stack: string[] = [...roots];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (out.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj === undefined) continue;
    out.add(oid);
    if (obj.type === 'commit') {
      const commit = getCommit(repo, oid);
      if (commit === undefined) continue;
      stack.push(commit.tree);
      for (const parent of commit.parents) stack.push(parent);
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const entry of getTree(repo, oid)) {
        if (entry.mode !== '160000') stack.push(entry.oid);
      }
    }
  }
}

/**
 * What a fetching client already holds: reachable from `roots`, except a
 * commit named in `shallow` is held without its parents (a shallow clone's
 * boundary commit has no history behind it on the client).
 */
function collectHeld(repo: Repo, roots: Iterable<string>, shallow: Set<string>, out: Set<string>): void {
  const stack: string[] = [...roots];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (out.has(oid)) continue;
    const obj = repo.objects.get(oid);
    if (obj === undefined) continue;
    out.add(oid);
    if (obj.type === 'commit') {
      const commit = getCommit(repo, oid);
      if (commit === undefined) continue;
      stack.push(commit.tree);
      if (!shallow.has(oid)) {
        for (const parent of commit.parents) stack.push(parent);
      }
    } else if (obj.type === 'tag') {
      stack.push(parseTag(obj.data).object);
    } else if (obj.type === 'tree') {
      for (const entry of getTree(repo, oid)) {
        if (entry.mode !== '160000') stack.push(entry.oid);
      }
    }
  }
}

interface FetchPlan {
  objects: GitObject[];
  shallow: string[];
  unshallow: string[];
}

/**
 * Objects a fetch should send: reachable from `wants`, minus what the client
 * already holds (`haves`), with an optional commit-depth limit. `clientShallow`
 * lists boundaries the client already treats as shallow.
 */
function computeFetch(
  repo: Repo,
  wants: string[],
  haves: string[],
  depth: number | null,
  clientShallow: string[],
): FetchPlan {
  const held = new Set<string>();
  if (haves.length > 0) collectHeld(repo, haves, new Set(clientShallow), held);
  const send = new Map<string, GitObject>();
  const addObj = (oid: string): void => {
    if (held.has(oid) || send.has(oid)) return;
    const obj = repo.objects.get(oid);
    if (obj !== undefined) send.set(oid, obj);
  };
  const addTreeRecursive = (treeOid: string): void => {
    const stack: string[] = [treeOid];
    while (stack.length > 0) {
      const oid = stack.pop() as string;
      if (held.has(oid) || send.has(oid)) continue;
      const obj = repo.objects.get(oid);
      if (obj === undefined || obj.type !== 'tree') continue;
      send.set(oid, obj);
      for (const entry of getTree(repo, oid)) {
        if (entry.mode === '160000') continue;
        if (entry.mode === '40000') stack.push(entry.oid);
        else addObj(entry.oid);
      }
    }
  };
  const shallow: string[] = [];
  const unshallow: string[] = [];
  const seenCommit = new Set<string>();
  const queue: Array<[string, number]> = [];
  for (const want of wants) {
    const obj = repo.objects.get(want);
    if (obj === undefined) continue;
    if (obj.type === 'tag') {
      addObj(want);
      const target = parseTag(obj.data).object;
      const targetObj = repo.objects.get(target);
      if (targetObj !== undefined && targetObj.type === 'commit') queue.push([target, 0]);
      else if (targetObj !== undefined) addObj(target);
    } else if (obj.type === 'commit') {
      queue.push([want, 0]);
    } else {
      addObj(want);
    }
  }
  let qi = 0;
  while (qi < queue.length) {
    const entry = queue[qi++] as [string, number];
    const oid = entry[0];
    const d = entry[1];
    if (seenCommit.has(oid)) continue;
    seenCommit.add(oid);
    const commit = getCommit(repo, oid);
    if (commit === undefined) continue;
    addObj(oid);
    addTreeRecursive(commit.tree);
    const atCutoff = depth !== null && d === depth - 1;
    if (atCutoff) {
      if (commit.parents.length > 0) shallow.push(oid);
      continue;
    }
    for (const parent of commit.parents) queue.push([parent, d + 1]);
  }
  for (const boundary of clientShallow) {
    const commit = getCommit(repo, boundary);
    if (commit !== undefined && commit.parents.some((p) => seenCommit.has(p))) {
      unshallow.push(boundary);
    }
  }
  return { objects: [...send.values()], shallow, unshallow };
}

// ------------------------------------------------------------------ trees as file maps

interface FlatFile {
  oid: string;
  mode: string;
}

/** Flatten a tree into path -> file (recursive, gitlinks skipped). */
function flattenTree(repo: Repo, treeOid: string, out: Map<string, FlatFile>): void {
  const stack: Array<[string, string]> = [[treeOid, '']];
  while (stack.length > 0) {
    const item = stack.pop() as [string, string];
    const oid = item[0];
    const prefix = item[1];
    for (const entry of getTree(repo, oid)) {
      const path = prefix === '' ? entry.name : prefix + '/' + entry.name;
      if (entry.mode === '40000') stack.push([entry.oid, path]);
      else if (entry.mode !== '160000') out.set(path, { oid: entry.oid, mode: entry.mode });
    }
  }
}

function treeOfCommit(repo: Repo, commitOid: string): string | null {
  const commit = getCommit(repo, commitOid);
  return commit === undefined ? null : commit.tree;
}

/** Build (and store) a tree object from a flat file map. */
function buildTreeFromFiles(repo: Repo, files: Map<string, FlatFile>): string {
  const build = (paths: Array<[string, FlatFile]>): string => {
    const entries: TreeEntry[] = [];
    const dirs = new Map<string, Array<[string, FlatFile]>>();
    for (const item of paths) {
      const path = item[0];
      const file = item[1];
      const slash = path.indexOf('/');
      if (slash < 0) {
        entries.push({ mode: file.mode, name: path, oid: file.oid });
      } else {
        const dir = path.slice(0, slash);
        const rest = path.slice(slash + 1);
        let list = dirs.get(dir);
        if (list === undefined) {
          list = [];
          dirs.set(dir, list);
        }
        list.push([rest, file]);
      }
    }
    for (const dirEntry of dirs) {
      entries.push({ mode: '40000', name: dirEntry[0], oid: build(dirEntry[1]) });
    }
    const data = buildTreeBytes(entries);
    const oid = hashObject('tree', data);
    if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', data });
    return oid;
  };
  return build([...files.entries()]);
}

/**
 * Set or delete one path in a tree, rebuilding parents bottom-up.
 * Returns the new tree oid, or null when the tree becomes empty.
 */
function updateTreeAt(
  repo: Repo,
  treeOid: string | null,
  segments: string[],
  blobOid: string | null,
): string | null {
  const entries: TreeEntry[] = treeOid === null ? [] : [...getTree(repo, treeOid)];
  const head = segments[0] as string;
  const rest = segments.slice(1);
  if (rest.length === 0) {
    const idx = entries.findIndex((e) => e.name === head && e.mode !== '40000');
    if (blobOid === null) {
      if (idx >= 0) entries.splice(idx, 1);
    } else if (idx >= 0) {
      entries[idx] = { mode: '100644', name: head, oid: blobOid };
    } else {
      entries.push({ mode: '100644', name: head, oid: blobOid });
    }
  } else {
    const idx = entries.findIndex((e) => e.name === head && e.mode === '40000');
    const subOid = idx >= 0 ? (entries[idx] as TreeEntry).oid : null;
    const newSub = updateTreeAt(repo, subOid, rest, blobOid);
    if (newSub === null) {
      if (idx >= 0) entries.splice(idx, 1);
    } else if (idx >= 0) {
      entries[idx] = { mode: '40000', name: head, oid: newSub };
    } else {
      entries.push({ mode: '40000', name: head, oid: newSub });
    }
  }
  if (entries.length === 0) return null;
  const data = buildTreeBytes(entries);
  const oid = hashObject('tree', data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type: 'tree', data });
  return oid;
}

/** Find the blob oid at `segments` in a tree, or null. */
function blobAtPath(repo: Repo, treeOid: string | null, segments: string[]): string | null {
  let current = treeOid;
  for (let i = 0; i < segments.length; i += 1) {
    if (current === null) return null;
    const segment = segments[i] as string;
    const entries = getTree(repo, current);
    const entry = entries.find((e) => e.name === segment);
    if (entry === undefined) return null;
    if (i === segments.length - 1) {
      return entry.mode === '40000' ? null : entry.oid;
    }
    if (entry.mode !== '40000') return null;
    current = entry.oid;
  }
  return null;
}

/** Create a commit object in the repo and return its oid. */
function makeCommit(repo: Repo, treeOid: string, parents: string[], message: string): string {
  const timestamp = EPOCH + repo.commitSeq;
  repo.commitSeq += 1;
  const data = buildCommitBytes(treeOid, parents, message, timestamp);
  const oid = hashObject('commit', data);
  repo.objects.set(oid, { type: 'commit', data });
  return oid;
}

function ensureEmptyTree(repo: Repo): string {
  if (!repo.objects.has(EMPTY_TREE_OID)) {
    repo.objects.set(EMPTY_TREE_OID, { type: 'tree', data: Buffer.alloc(0) });
  }
  return EMPTY_TREE_OID;
}

// ------------------------------------------------------------------ contents commits

interface FileChangeResult {
  commitSha: string;
  blobSha: string | null;
  created: boolean;
}

/**
 * Apply a contents PUT/DELETE: write or remove one file on a branch (creating
 * the branch from the default tip when it does not exist yet), as a real git
 * commit. Throws {status, message} on a stale sha.
 */
function applyFileChange(
  repo: Repo,
  branch: string,
  segments: string[],
  content: Buffer | null,
  message: string,
  expectedSha: string | undefined,
): FileChangeResult {
  const ref = 'refs/heads/' + branch;
  const tip = repo.refs.get(ref);
  const baseTree = tip === undefined ? null : treeOfCommit(repo, tip);
  const currentBlob = blobAtPath(repo, baseTree, segments);
  if (expectedSha !== undefined && expectedSha !== '' && currentBlob !== expectedSha) {
    throw { status: 409, message: 'sha does not match the current blob' };
  }
  const created = currentBlob === null;
  let blobSha: string | null = null;
  if (content !== null) {
    blobSha = hashObject('blob', content);
    if (!repo.objects.has(blobSha)) repo.objects.set(blobSha, { type: 'blob', data: content });
  }
  let newTree = updateTreeAt(repo, baseTree, segments, blobSha);
  if (newTree === null) newTree = ensureEmptyTree(repo);
  const parents = tip === undefined ? [] : [tip];
  const commitSha = makeCommit(repo, newTree, parents, message);
  repo.refs.set(ref, commitSha);
  bumpRepo(repo);
  return { commitSha, blobSha, created };
}

// ------------------------------------------------------------------ pull requests

/** Three-way conflict check for a pull request (no changes applied). */
function prHasConflict(repo: Repo, pr: Pull): boolean {
  const headTip = repo.refs.get('refs/heads/' + pr.headRef);
  const baseTip = repo.refs.get('refs/heads/' + pr.baseRef);
  if (headTip === undefined || baseTip === undefined) return false;
  const baseTree = treeOfCommit(repo, pr.baseSha);
  const headTree = treeOfCommit(repo, headTip);
  const curTree = treeOfCommit(repo, baseTip);
  if (baseTree === null || headTree === null || curTree === null) return false;
  const baseFiles = new Map<string, FlatFile>();
  const headFiles = new Map<string, FlatFile>();
  const curFiles = new Map<string, FlatFile>();
  flattenTree(repo, baseTree, baseFiles);
  flattenTree(repo, headTree, headFiles);
  flattenTree(repo, curTree, curFiles);
  const paths = new Set<string>([...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of paths) {
    const b = baseFiles.get(path);
    const h = headFiles.get(path);
    const c = curFiles.get(path);
    if (h !== undefined && (b === undefined || h.oid !== b.oid)) {
      if (c !== undefined && b !== undefined && c.oid !== b.oid && c.oid !== h.oid) return true;
      if (c === undefined && b !== undefined) return true;
    } else if (h === undefined && b !== undefined) {
      if (c !== undefined && c.oid !== b.oid) return true;
    }
  }
  return false;
}

/** Squash-merge a pull request onto its base branch. Returns null on conflict. */
function mergePull(repo: Repo, pr: Pull): string | null {
  if (pr.merged) return null;
  if (prHasConflict(repo, pr)) return null;
  const headTip = repo.refs.get('refs/heads/' + pr.headRef);
  const baseTip = repo.refs.get('refs/heads/' + pr.baseRef);
  if (headTip === undefined || baseTip === undefined) return null;
  const baseTree = treeOfCommit(repo, pr.baseSha);
  const headTree = treeOfCommit(repo, headTip);
  const curTree = treeOfCommit(repo, baseTip);
  if (baseTree === null || headTree === null || curTree === null) return null;
  const baseFiles = new Map<string, FlatFile>();
  const headFiles = new Map<string, FlatFile>();
  const merged = new Map<string, FlatFile>();
  flattenTree(repo, baseTree, baseFiles);
  flattenTree(repo, headTree, headFiles);
  flattenTree(repo, curTree, merged);
  const paths = new Set<string>([...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of paths) {
    const b = baseFiles.get(path);
    const h = headFiles.get(path);
    if (h !== undefined && (b === undefined || h.oid !== b.oid)) {
      merged.set(path, h);
    } else if (h === undefined && b !== undefined) {
      merged.delete(path);
    }
  }
  const treeOid = buildTreeFromFiles(repo, merged);
  const sha = makeCommit(repo, treeOid, [baseTip], 'Merge pull request #' + pr.number + ': ' + pr.title);
  repo.refs.set('refs/heads/' + pr.baseRef, sha);
  bumpRepo(repo);
  pr.state = 'closed';
  pr.merged = true;
  pr.mergedAt = FIXED_ISO;
  pr.mergeCommitSha = sha;
  return sha;
}

interface FileChange {
  filename: string;
  status: string;
  additions: number;
  deletions: number;
  changes: number;
}

/** Diff base tip tree vs head tip tree, flattened to file paths. */
function diffPullFiles(repo: Repo, baseSha: string, headSha: string): FileChange[] {
  const baseTree = treeOfCommit(repo, baseSha);
  const headTree = treeOfCommit(repo, headSha);
  const baseFiles = new Map<string, FlatFile>();
  const headFiles = new Map<string, FlatFile>();
  if (baseTree !== null) flattenTree(repo, baseTree, baseFiles);
  if (headTree !== null) flattenTree(repo, headTree, headFiles);
  const paths = new Set<string>([...baseFiles.keys(), ...headFiles.keys()]);
  const out: FileChange[] = [];
  const blobText = (oid: string): string => {
    const obj = repo.objects.get(oid);
    return obj === undefined ? '' : obj.data.toString('utf8');
  };
  for (const path of [...paths].sort()) {
    const b = baseFiles.get(path);
    const h = headFiles.get(path);
    if (b === undefined && h !== undefined) {
      const lines = countLines(blobText(h.oid));
      out.push({ filename: path, status: 'added', additions: lines, deletions: 0, changes: lines });
    } else if (b !== undefined && h === undefined) {
      const lines = countLines(blobText(b.oid));
      out.push({ filename: path, status: 'removed', additions: 0, deletions: lines, changes: lines });
    } else if (b !== undefined && h !== undefined && b.oid !== h.oid) {
      const diff = lineDiff(blobText(b.oid), blobText(h.oid));
      out.push({
        filename: path,
        status: 'modified',
        additions: diff.add,
        deletions: diff.del,
        changes: diff.add + diff.del,
      });
    }
  }
  return out;
}

/** Commits reachable from `tip`, newest first (first-parent order via stack). */
function listCommits(repo: Repo, tip: string): Array<{ sha: string; message: string }> {
  const out: Array<{ sha: string; message: string }> = [];
  const seen = new Set<string>();
  const stack: string[] = [tip];
  while (stack.length > 0) {
    const oid = stack.pop() as string;
    if (seen.has(oid)) continue;
    seen.add(oid);
    const obj = repo.objects.get(oid);
    if (obj === undefined || obj.type !== 'commit') continue;
    const commit = getCommit(repo, oid);
    if (commit === undefined) continue;
    const blank = obj.data.indexOf('\n\n');
    const message = blank < 0 ? '' : obj.data.subarray(blank + 2).toString('utf8');
    out.push({ sha: oid, message });
    for (let i = commit.parents.length - 1; i >= 0; i -= 1) {
      stack.push(commit.parents[i] as string);
    }
  }
  return out;
}

/** Resolve a branch name, full ref, or oid to a commit oid. */
function resolveRefTarget(repo: Repo, ref: string): string | null {
  if (repo.refs.has(ref)) return repo.refs.get(ref) as string;
  const asBranch = repo.refs.get('refs/heads/' + ref);
  if (asBranch !== undefined) return asBranch;
  if (repo.objects.has(ref)) return ref;
  return null;
}

// ------------------------------------------------------------------ HTTP plumbing

function nextReqId(): string {
  reqSeq += 1;
  return 'req-' + reqSeq;
}

function readBody(req: http.IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function sendJson(
  res: http.ServerResponse,
  status: number,
  obj: unknown,
  extra: Record<string, string> = {},
): void {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'x-github-request-id': nextReqId(),
    'x-oauth-scopes': 'repo, read:org',
    ...extra,
  });
  res.end(body);
}

function sendRestError(res: http.ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function isAuthed(req: http.IncomingMessage): boolean {
  const token = process.env.MAKEFUN_SHOP_TOKEN ?? '';
  if (token === '') return false;
  return req.headers.authorization === 'Bearer ' + token;
}

function parseJsonBody(body: Buffer): unknown {
  if (body.length === 0) return {};
  return JSON.parse(body.toString('utf8'));
}

function paginationParams(query: URLSearchParams): { perPage: number; page: number } {
  const perPageRaw = Number.parseInt(query.get('per_page') ?? '', 10);
  const pageRaw = Number.parseInt(query.get('page') ?? '', 10);
  const perPage = Number.isFinite(perPageRaw) ? Math.min(100, Math.max(1, perPageRaw)) : 30;
  const page = Number.isFinite(pageRaw) ? Math.max(1, pageRaw) : 1;
  return { perPage, page };
}

function paginate<T>(
  items: T[],
  query: URLSearchParams,
  req: http.IncomingMessage,
  path: string,
): { page: T[]; link: string | null } {
  const { perPage, page } = paginationParams(query);
  const start = (page - 1) * perPage;
  const slice = items.slice(start, start + perPage);
  let link: string | null = null;
  if (start + perPage < items.length) {
    const host = req.headers.host ?? '127.0.0.1';
    const nextQuery = new URLSearchParams(query);
    nextQuery.set('per_page', String(perPage));
    nextQuery.set('page', String(page + 1));
    link = '<http://' + host + path + '?' + nextQuery.toString() + '>; rel="next"';
  }
  return { page: slice, link };
}

// ------------------------------------------------------------------ REST serializers

function repoJson(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    node_id: b64uEncode('Repository:' + repo.id),
    name: repo.name,
    full_name: repo.owner + '/' + repo.name,
    owner: { login: repo.owner, id: VIEWER_ID, type: 'User' },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    fork: false,
    archived: false,
    has_issues: true,
    has_pull_requests: true,
  };
}

function issueJson(issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    node_id: b64uEncode('Issue:' + issue.repoId + ':' + issue.number),
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((l) => ({ name: l.name, color: l.color })),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
    comments: issue.comments.length,
  };
}

function pullJson(pr: Pull): Record<string, unknown> {
  return {
    id: pr.id,
    node_id: b64uEncode('PullRequest:' + pr.repoId + ':' + pr.number),
    number: pr.number,
    title: pr.title,
    body: pr.body,
    state: pr.state,
    merged: pr.merged,
    merged_at: pr.merged ? pr.mergedAt : null,
    merge_commit_sha: pr.merged ? pr.mergeCommitSha : null,
    head: { ref: pr.headRef, sha: pr.headSha, label: VIEWER_LOGIN + ':' + pr.headRef },
    base: { ref: pr.baseRef, sha: pr.baseSha, label: VIEWER_LOGIN + ':' + pr.baseRef },
    user: { login: VIEWER_LOGIN, id: VIEWER_ID, type: 'User' },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

// ------------------------------------------------------------------ REST v3

async function handleRest(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  segments: string[],
  query: URLSearchParams,
  path: string,
): Promise<boolean> {
  if (segments.length === 0 || segments[0] !== 'api' || segments[1] !== 'v3') return false;
  const method = req.method ?? 'GET';
  if (!isAuthed(req)) {
    sendRestError(res, 401, 'Requires authentication');
    return true;
  }
  const rest = segments.slice(2);

  // GET /api/v3/  and  GET /api/v3/meta
  if (rest.length === 0) {
    if (method !== 'GET') return sendRestError(res, 404, 'Not Found'), true;
    sendJson(res, 200, {
      current_user_url: '/api/v3/user',
      repository_url: '/api/v3/repos/{owner}/{repo}',
      user_repositories_url: '/api/v3/user/repos',
    });
    return true;
  }
  if (rest.length === 1 && rest[0] === 'meta') {
    if (method !== 'GET') return sendRestError(res, 404, 'Not Found'), true;
    sendJson(res, 200, { installed_version: '1.0.0' });
    return true;
  }
  if (rest.length === 1 && rest[0] === 'user') {
    if (method !== 'GET') return sendRestError(res, 404, 'Not Found'), true;
    sendJson(res, 200, {
      login: VIEWER_LOGIN,
      id: VIEWER_ID,
      name: VIEWER_NAME,
      email: VIEWER_EMAIL,
      type: 'User',
    });
    return true;
  }

  // /api/v3/user/repos
  if (rest.length === 2 && rest[0] === 'user' && rest[1] === 'repos') {
    if (method === 'GET') {
      const all = [...reposByName.values()].sort((a, b) => a.id - b.id);
      const { page, link } = paginate(all, query, req, path);
      sendJson(
        res,
        200,
        page.map((r) => repoJson(r)),
        link !== null ? { link } : {},
      );
      return true;
    }
    if (method === 'POST') {
      let body: unknown;
      try {
        body = parseJsonBody(await readBody(req));
      } catch {
        return sendRestError(res, 400, 'Invalid JSON'), true;
      }
      if (!isRecord(body)) return sendRestError(res, 400, 'Invalid body'), true;
      const name = asString(body.name);
      if (name === '') return sendRestError(res, 422, 'name is required'), true;
      if (reposByName.has(name)) {
        return sendRestError(res, 422, 'name already exists on this account'), true;
      }
      const repo = createRepo(
        name,
        body.private === true,
        asString(body.description),
      );
      sendJson(res, 201, repoJson(repo));
      return true;
    }
    return sendRestError(res, 404, 'Not Found'), true;
  }

  // /api/v3/repos/{owner}/{repo}[...]
  if (rest.length >= 3 && rest[0] === 'repos') {
    const owner = decodeURIComponent(rest[1] as string);
    const repoName = decodeURIComponent(rest[2] as string);
    const repo = getRepo(owner, repoName);
    const tail = rest.slice(3);
    if (repo === undefined) return sendRestError(res, 404, 'Not Found'), true;

    // GET/PATCH/DELETE /repos/{o}/{r}
    if (tail.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'PATCH') {
        let body: unknown;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          return sendRestError(res, 400, 'Invalid JSON'), true;
        }
        if (isRecord(body)) {
          if (typeof body.description === 'string') repo.description = body.description;
          if (typeof body.private === 'boolean') repo.private = body.private;
        }
        sendJson(res, 200, repoJson(repo));
        return true;
      }
      if (method === 'DELETE') {
        reposByName.delete(repo.name);
        reposById.delete(repo.id);
        res.writeHead(204, { 'x-github-request-id': nextReqId() });
        res.end();
        return true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // GET /branches  and  GET /branches/{branch}
    if (tail[0] === 'branches') {
      if (method !== 'GET') return sendRestError(res, 404, 'Not Found'), true;
      if (tail.length === 1) {
        const list: Array<Record<string, unknown>> = [];
        for (const entry of repo.refs) {
          if (entry[0].startsWith('refs/heads/')) {
            list.push({ name: entry[0].slice('refs/heads/'.length), commit: { sha: entry[1] } });
          }
        }
        sendJson(res, 200, list);
        return true;
      }
      if (tail.length === 2) {
        const sha = repo.refs.get('refs/heads/' + decodeURIComponent(tail[1] as string));
        if (sha === undefined) return sendRestError(res, 404, 'Not Found'), true;
        sendJson(res, 200, { name: decodeURIComponent(tail[1] as string), commit: { sha } });
        return true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // POST /git/refs  and  GET /git/refs/heads/{branch}
    if (tail[0] === 'git' && tail[1] === 'refs') {
      if (method === 'POST' && tail.length === 2) {
        let body: unknown;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          return sendRestError(res, 400, 'Invalid JSON'), true;
        }
        if (!isRecord(body)) return sendRestError(res, 400, 'Invalid body'), true;
        const ref = asString(body.ref);
        const sha = asString(body.sha);
        if (!ref.startsWith('refs/') || !/^[0-9a-f]{40}$/.test(sha)) {
          return sendRestError(res, 422, 'Invalid ref or sha'), true;
        }
        if (repo.refs.has(ref)) {
          return sendRestError(res, 422, 'Reference already exists'), true;
        }
        if (!repo.objects.has(sha)) {
          return sendRestError(res, 422, 'Object does not exist'), true;
        }
        repo.refs.set(ref, sha);
        bumpRepo(repo);
        sendJson(res, 201, { ref, object: { sha } });
        return true;
      }
      if (method === 'GET' && tail.length >= 3) {
        const refName = tail.slice(2).map((s) => decodeURIComponent(s)).join('/');
        const sha = repo.refs.get(refName);
        if (sha === undefined) return sendRestError(res, 404, 'Not Found'), true;
        sendJson(res, 200, { ref: refName, object: { sha } });
        return true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // GET /commits
    if (tail[0] === 'commits' && tail.length === 1) {
      if (method !== 'GET') return sendRestError(res, 404, 'Not Found'), true;
      const shaParam = query.get('sha');
      let tip: string | undefined;
      if (shaParam === null || shaParam === '') {
        tip = repo.refs.get('refs/heads/' + repo.defaultBranch);
      } else {
        tip = resolveRefTarget(repo, shaParam) ?? undefined;
      }
      if (tip === undefined) return sendRestError(res, 404, 'Not Found'), true;
      const commits = listCommits(repo, tip).map((c) => ({
        sha: c.sha,
        commit: { message: c.message, author: { name: VIEWER_LOGIN, email: VIEWER_EMAIL }, committer: { name: VIEWER_LOGIN, email: VIEWER_EMAIL } },
      }));
      sendJson(res, 200, commits);
      return true;
    }

    // contents: PUT/GET/DELETE /contents/{path...}
    if (tail[0] === 'contents') {
      const contentPath = tail.slice(1).map((s) => decodeURIComponent(s)).join('/');
      if (method === 'PUT') {
        let body: unknown;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          return sendRestError(res, 400, 'Invalid JSON'), true;
        }
        if (!isRecord(body)) return sendRestError(res, 400, 'Invalid body'), true;
        const message = asString(body.message);
        const contentB64 = asString(body.content);
        const branch = asString(body.branch) || repo.defaultBranch;
        const expectedSha = typeof body.sha === 'string' ? body.sha : undefined;
        if (contentPath === '') return sendRestError(res, 422, 'path is required'), true;
        let content: Buffer;
        try {
          content = Buffer.from(contentB64, 'base64');
        } catch {
          return sendRestError(res, 400, 'Invalid base64 content'), true;
        }
        const segments = contentPath.split('/').filter((s) => s !== '');
        try {
          const result = applyFileChange(repo, branch, segments, content, message, expectedSha);
          sendJson(res, result.created ? 201 : 200, {
            content: {
              name: segments[segments.length - 1],
              path: contentPath,
              sha: result.blobSha,
              size: content.length,
              encoding: 'base64',
              content: contentB64,
            },
            commit: { sha: result.commitSha },
          });
        } catch (err) {
          if (isRecord(err) && typeof err.status === 'number') {
            return sendRestError(res, err.status, asString(err.message)), true;
          }
          throw err;
        }
        return true;
      }
      if (method === 'GET') {
        const refParam = query.get('ref');
        let tip: string | undefined;
        if (refParam === null || refParam === '') {
          tip = repo.refs.get('refs/heads/' + repo.defaultBranch);
        } else {
          tip = resolveRefTarget(repo, refParam) ?? undefined;
        }
        if (tip === undefined) return sendRestError(res, 404, 'Not Found'), true;
        const treeOid = treeOfCommit(repo, tip);
        if (treeOid === null) return sendRestError(res, 404, 'Not Found'), true;
        if (contentPath === '') {
          const children = getTree(repo, treeOid).map((e) => ({
            type: e.mode === '40000' ? 'dir' : 'file',
            name: e.name,
            path: e.name,
            sha: e.oid,
          }));
          sendJson(res, 200, children);
          return true;
        }
        const segments = contentPath.split('/').filter((s) => s !== '');
        let currentTree: string | null = treeOid;
        let found: TreeEntry | undefined;
        for (let i = 0; i < segments.length; i += 1) {
          if (currentTree === null) {
            found = undefined;
            break;
          }
          found = getTree(repo, currentTree).find((e) => e.name === segments[i]);
          if (found === undefined) break;
          if (i < segments.length - 1) {
            if (found.mode !== '40000') {
              found = undefined;
              break;
            }
            currentTree = found.oid;
          }
        }
        if (found === undefined) return sendRestError(res, 404, 'Not Found'), true;
        if (found.mode === '40000') {
          const children = getTree(repo, found.oid).map((e) => ({
            type: e.mode === '40000' ? 'dir' : 'file',
            name: e.name,
            path: contentPath + '/' + e.name,
            sha: e.oid,
          }));
          sendJson(res, 200, children);
          return true;
        }
        const obj = repo.objects.get(found.oid);
        if (obj === undefined) return sendRestError(res, 404, 'Not Found'), true;
        sendJson(res, 200, {
          type: 'file',
          encoding: 'base64',
          name: found.name,
          path: contentPath,
          sha: found.oid,
          size: obj.data.length,
          content: obj.data.toString('base64'),
        });
        return true;
      }
      if (method === 'DELETE') {
        let body: unknown;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          return sendRestError(res, 400, 'Invalid JSON'), true;
        }
        if (!isRecord(body)) return sendRestError(res, 400, 'Invalid body'), true;
        const message = asString(body.message);
        const branch = asString(body.branch) || repo.defaultBranch;
        const expectedSha = typeof body.sha === 'string' ? body.sha : undefined;
        if (contentPath === '') return sendRestError(res, 422, 'path is required'), true;
        const segments = contentPath.split('/').filter((s) => s !== '');
        try {
          const result = applyFileChange(repo, branch, segments, null, message, expectedSha);
          sendJson(res, 200, { commit: { sha: result.commitSha } });
        } catch (err) {
          if (isRecord(err) && typeof err.status === 'number') {
            return sendRestError(res, err.status, asString(err.message)), true;
          }
          throw err;
        }
        return true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // labels: GET/POST /labels
    if (tail[0] === 'labels' && tail.length === 1) {
      if (method === 'GET') {
        sendJson(res, 200, [...repo.labels.values()].map((l) => ({ name: l.name, color: l.color })));
        return true;
      }
      if (method === 'POST') {
        let body: unknown;
        try {
          body = parseJsonBody(await readBody(req));
        } catch {
          return sendRestError(res, 400, 'Invalid JSON'), true;
        }
        if (!isRecord(body)) return sendRestError(res, 400, 'Invalid body'), true;
        const name = asString(body.name);
        if (name === '') return sendRestError(res, 422, 'name is required'), true;
        const existing = repo.labels.get(name);
        if (existing !== undefined) {
          sendJson(res, 201, { name: existing.name, color: existing.color });
          return true;
        }
        const label: Label = { name, color: asString(body.color) || 'ededed' };
        repo.labels.set(name, label);
        sendJson(res, 201, { name: label.name, color: label.color });
        return true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // issues: POST/GET /issues, GET/PATCH /issues/{n}, POST/GET /issues/{n}/comments
    if (tail[0] === 'issues') {
      if (tail.length === 1) {
        if (method === 'POST') {
          let body: unknown;
          try {
            body = parseJsonBody(await readBody(req));
          } catch {
            return sendRestError(res, 400, 'Invalid JSON'), true;
          }
          if (!isRecord(body)) return sendRestError(res, 400, 'Invalid body'), true;
          const title = asString(body.title);
          if (title === '') return sendRestError(res, 422, 'title is required'), true;
          const labels: Label[] = [];
          if (Array.isArray(body.labels)) {
            for (const raw of body.labels) {
              const labelName = typeof raw === 'string' ? raw : isRecord(raw) ? asString(raw.name) : '';
              const found = repo.labels.get(labelName);
              if (found === undefined) {
                return sendRestError(res, 422, 'label "' + labelName + '" does not exist'), true;
              }
              labels.push(found);
            }
          }
          const issue: Issue = {
            id: ++entitySeq,
            number: repo.nextNumber++,
            repoId: repo.id,
            title,
            body: asString(body.body),
            state: 'open',
            labels,
            comments: [],
            _json: null,
          };
          repo.issues.set(issue.number, issue);
          sendJson(res, 201, issueJson(issue));
          return true;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          const direction = query.get('direction') ?? 'desc';
          let list = [...repo.issues.values()];
          if (state === 'open') list = list.filter((i) => i.state === 'open');
          else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
          if (direction === 'asc') list.sort((a, b) => a.number - b.number);
          else list.sort((a, b) => b.number - a.number);
          const { page, link } = paginate(list, query, req, path);
          sendJson(
            res,
            200,
            page.map((i) => issueJson(i)),
            link !== null ? { link } : {},
          );
          return true;
        }
        return sendRestError(res, 404, 'Not Found'), true;
      }
      const num = Number.parseInt(tail[1] as string, 10);
      if (!Number.isSafeInteger(num)) return sendRestError(res, 404, 'Not Found'), true;
      const issue = repo.issues.get(num);
      if (tail.length === 2) {
        if (issue === undefined) return sendRestError(res, 404, 'Not Found'), true;
        if (method === 'GET') {
          if (issue._json !== null) {
            res.writeHead(200, {
              'content-type': 'application/json; charset=utf-8',
              'x-github-request-id': nextReqId(),
              'x-oauth-scopes': 'repo, read:org',
            });
            res.end(issue._json);
            return true;
          }
          const serialized = JSON.stringify(issueJson(issue));
          issue._json = serialized;
          res.writeHead(200, {
            'content-type': 'application/json; charset=utf-8',
            'x-github-request-id': nextReqId(),
            'x-oauth-scopes': 'repo, read:org',
          });
          res.end(serialized);
          return true;
        }
        if (method === 'PATCH') {
          let body: unknown;
          try {
            body = parseJsonBody(await readBody(req));
          } catch {
            return sendRestError(res, 400, 'Invalid JSON'), true;
          }
          if (isRecord(body)) {
            if (body.state === 'open' || body.state === 'closed') issue.state = body.state;
            if (typeof body.title === 'string') issue.title = body.title;
            if (typeof body.body === 'string') issue.body = body.body;
            issue._json = null;
          }
          sendJson(res, 200, issueJson(issue));
          return true;
        }
        return sendRestError(res, 404, 'Not Found'), true;
      }
      if (tail.length === 3 && tail[2] === 'comments') {
        if (issue === undefined) return sendRestError(res, 404, 'Not Found'), true;
        if (method === 'GET') {
          sendJson(
            res,
            200,
            issue.comments.map((c) => ({ id: c.id, body: c.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID } })),
          );
          return true;
        }
        if (method === 'POST') {
          let body: unknown;
          try {
            body = parseJsonBody(await readBody(req));
          } catch {
            return sendRestError(res, 400, 'Invalid JSON'), true;
          }
          if (!isRecord(body)) return sendRestError(res, 400, 'Invalid body'), true;
          const comment: Comment = { id: ++entitySeq, body: asString(body.body) };
          issue.comments.push(comment);
          issue._json = null;
          sendJson(res, 201, { id: comment.id, body: comment.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID } });
          return true;
        }
        return sendRestError(res, 404, 'Not Found'), true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }

    // pulls: POST/GET /pulls, GET /pulls/{n}, GET /pulls/{n}/files, PUT /pulls/{n}/merge
    if (tail[0] === 'pulls') {
      if (tail.length === 1) {
        if (method === 'POST') {
          let body: unknown;
          try {
            body = parseJsonBody(await readBody(req));
          } catch {
            return sendRestError(res, 400, 'Invalid JSON'), true;
          }
          if (!isRecord(body)) return sendRestError(res, 400, 'Invalid body'), true;
          const head = asString(body.head);
          const base = asString(body.base);
          if (head === '' || base === '') return sendRestError(res, 422, 'head and base are required'), true;
          const headSha = repo.refs.get('refs/heads/' + head);
          const baseSha = repo.refs.get('refs/heads/' + base);
          if (headSha === undefined || baseSha === undefined) {
            return sendRestError(res, 422, 'head or base branch does not exist'), true;
          }
          if (head === base) return sendRestError(res, 422, 'head and base are the same'), true;
          for (const existing of repo.pulls.values()) {
            if (existing.state === 'open' && existing.headRef === head && existing.baseRef === base) {
              return sendRestError(res, 422, 'a pull request for this head already exists'), true;
            }
          }
          const pr: Pull = {
            id: ++entitySeq,
            number: repo.nextNumber++,
            repoId: repo.id,
            title: asString(body.title),
            body: asString(body.body),
            state: 'open',
            merged: false,
            mergedAt: '',
            mergeCommitSha: '',
            headRef: head,
            baseRef: base,
            headSha,
            baseSha,
          };
          repo.pulls.set(pr.number, pr);
          sendJson(res, 201, pullJson(pr));
          return true;
        }
        if (method === 'GET') {
          const state = query.get('state') ?? 'open';
          let list = [...repo.pulls.values()];
          if (state === 'open') list = list.filter((p) => p.state === 'open');
          else if (state === 'closed') list = list.filter((p) => p.state === 'closed');
          list.sort((a, b) => b.number - a.number);
          const { page, link } = paginate(list, query, req, path);
          sendJson(
            res,
            200,
            page.map((p) => pullJson(p)),
            link !== null ? { link } : {},
          );
          return true;
        }
        return sendRestError(res, 404, 'Not Found'), true;
      }
      const num = Number.parseInt(tail[1] as string, 10);
      if (!Number.isSafeInteger(num)) return sendRestError(res, 404, 'Not Found'), true;
      const pr = repo.pulls.get(num);
      if (tail.length === 2) {
        if (pr === undefined) return sendRestError(res, 404, 'Not Found'), true;
        if (method !== 'GET') return sendRestError(res, 404, 'Not Found'), true;
        sendJson(res, 200, pullJson(pr));
        return true;
      }
      if (tail.length === 3 && tail[2] === 'files') {
        if (pr === undefined) return sendRestError(res, 404, 'Not Found'), true;
        if (method !== 'GET') return sendRestError(res, 404, 'Not Found'), true;
        sendJson(res, 200, diffPullFiles(repo, pr.baseSha, pr.headSha));
        return true;
      }
      if (tail.length === 3 && tail[2] === 'merge') {
        if (pr === undefined) return sendRestError(res, 404, 'Not Found'), true;
        if (method !== 'PUT') return sendRestError(res, 404, 'Not Found'), true;
        try {
          await readBody(req);
        } catch {
          return sendRestError(res, 400, 'Invalid body'), true;
        }
        if (pr.merged) return sendRestError(res, 405, 'Pull request already merged'), true;
        const sha = mergePull(repo, pr);
        if (sha === null) return sendRestError(res, 405, 'Merge conflict'), true;
        sendJson(res, 200, {
          merged: true,
          sha,
          message: 'Merge pull request #' + pr.number + ': ' + pr.title,
        });
        return true;
      }
      return sendRestError(res, 404, 'Not Found'), true;
    }
  }
  return sendRestError(res, 404, 'Not Found'), true;
}

// ------------------------------------------------------------------ git smart HTTP

function sortedRefEntries(repo: Repo): Array<[string, string]> {
  const entries: Array<[string, string]> = [];
  for (const entry of repo.refs) entries.push([entry[0], entry[1]]);
  entries.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return entries;
}

function gitRequestIdHeader(): Record<string, string> {
  return { 'x-github-request-id': nextReqId() };
}

/** The v2 upload-pack advertisement is the same for every repository. */
const V2_ADV: Buffer = Buffer.concat([
  pktLine('version 2\n'),
  pktLine('agent=' + AGENT + '\n'),
  pktLine('ls-refs\n'),
  pktLine('fetch=shallow filter\n'),
  pktLine('object-format=sha1\n'),
  PKT_FLUSH,
]);

function handleInfoRefs(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  owner: string,
  repoName: string,
  service: string,
): void {
  const repo = getRepo(owner, repoName);
  if (repo === undefined) {
    sendRestError(res, 404, 'Not Found');
    return;
  }
  const isV2 =
    service === 'git-upload-pack' && req.headers['git-protocol'] === 'version=2';
  if (isV2) {
    res.writeHead(200, {
      'content-type': 'application/x-git-upload-pack-advertisement',
      ...gitRequestIdHeader(),
    });
    res.end(V2_ADV);
    return;
  }
  const cached = repo.v0AdvCache.get(service);
  if (cached !== undefined) {
    res.writeHead(200, {
      'content-type': 'application/x-' + service + '-advertisement',
      ...gitRequestIdHeader(),
    });
    res.end(cached);
    return;
  }
  const caps =
    service === 'git-upload-pack'
      ? 'side-band-64k shallow ofs-delta thin-pack agent=' + AGENT + ' symref=HEAD:refs/heads/main'
      : 'report-status side-band-64k delete-refs ofs-delta agent=' + AGENT + ' symref=HEAD:refs/heads/main';
  const parts: Buffer[] = [pktLine('# service=' + service + '\n'), PKT_FLUSH];
  const mainTip = repo.refs.get('refs/heads/main');
  if (mainTip === undefined) {
    parts.push(pktLine(ZERO_OID + ' capabilities^{}\0' + caps + '\n'));
  } else {
    parts.push(pktLine(mainTip + ' HEAD\0' + caps + '\n'));
    for (const refEntry of sortedRefEntries(repo)) {
      const name = refEntry[0];
      const oid = refEntry[1];
      parts.push(pktLine(oid + ' ' + name + '\n'));
      const obj = repo.objects.get(oid);
      if (obj !== undefined && obj.type === 'tag') {
        const target = parseTag(obj.data).object;
        parts.push(pktLine(target + ' ' + name + '^{}\n'));
      }
    }
  }
  parts.push(PKT_FLUSH);
  const out = Buffer.concat(parts);
  repo.v0AdvCache.set(service, out);
  res.writeHead(200, {
    'content-type': 'application/x-' + service + '-advertisement',
    ...gitRequestIdHeader(),
  });
  res.end(out);
}

function handleLsRefs(repo: Repo, lines: string[]): Buffer {
  let peel = false;
  let symrefs = false;
  const prefixes: string[] = [];
  for (const line of lines) {
    const text = line.replace(/\n$/, '');
    if (text === 'peel') peel = true;
    else if (text === 'symrefs') symrefs = true;
    else if (text.startsWith('ref-prefix ')) prefixes.push(text.slice('ref-prefix '.length));
  }
  const cacheKey = (peel ? 'p' : '') + (symrefs ? 's' : '') + '|' + prefixes.join(',');
  const cached = repo.lsRefsCache.get(cacheKey);
  if (cached !== undefined) return cached;
  const keep = (name: string): boolean =>
    prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
  const parts: Buffer[] = [];
  const mainTip = repo.refs.get('refs/heads/main');
  if (keep('HEAD')) {
    const headLine =
      (mainTip ?? ZERO_OID) +
      ' HEAD' +
      (symrefs ? ' symref-target:refs/heads/main' : '') +
      '\n';
    parts.push(pktLine(headLine));
  }
  for (const refEntry of sortedRefEntries(repo)) {
    const name = refEntry[0];
    const oid = refEntry[1];
    if (!keep(name)) continue;
    let line = oid + ' ' + name;
    const obj = repo.objects.get(oid);
    if (peel && obj !== undefined && obj.type === 'tag') {
      line += ' peeled:' + parseTag(obj.data).object;
    }
    parts.push(pktLine(line + '\n'));
  }
  parts.push(PKT_FLUSH);
  const out = Buffer.concat(parts);
  repo.lsRefsCache.set(cacheKey, out);
  return out;
}

function handleFetchV2(repo: Repo, lines: string[]): Buffer {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowReq: string[] = [];
  let depth: number | null = null;
  for (const line of lines) {
    const text = line.replace(/\n$/, '');
    if (text.startsWith('want ')) wants.push(text.slice(5).trim());
    else if (text.startsWith('have ')) haves.push(text.slice(5).trim());
    else if (text.startsWith('shallow ')) shallowReq.push(text.slice(8).trim());
    else if (text.startsWith('deepen ')) {
      const n = Number.parseInt(text.slice(7).trim(), 10);
      if (Number.isSafeInteger(n) && n > 0) depth = n;
    }
  }
  const cacheKey =
    'v2|' + wants.join(',') + '|' + haves.join(',') + '|' + shallowReq.join(',') + '|' + String(depth);
  const cached = repo.fetchCache.get(cacheKey);
  if (cached !== undefined) return cached;
  const plan = computeFetch(repo, wants, haves, depth, shallowReq);
  const pack = writePack(plan.objects);
  const parts: Buffer[] = [pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_DELIM];
  if (plan.shallow.length > 0 || plan.unshallow.length > 0) {
    parts.push(pktLine('shallow-info\n'));
    for (const oid of plan.shallow) parts.push(pktLine('shallow ' + oid + '\n'));
    for (const oid of plan.unshallow) parts.push(pktLine('unshallow ' + oid + '\n'));
    parts.push(PKT_DELIM);
  }
  parts.push(pktLine('packfile\n'));
  for (let off = 0; off < pack.length; off += 65515) {
    const chunk = pack.subarray(off, Math.min(pack.length, off + 65515));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  parts.push(PKT_FLUSH);
  const out = Buffer.concat(parts);
  repo.fetchCache.set(cacheKey, out);
  return out;
}

function handleFetchV0(repo: Repo, lines: string[]): Buffer {
  const wants: string[] = [];
  const haves: string[] = [];
  const shallowReq: string[] = [];
  let depth: number | null = null;
  let inSecondSection = false;
  for (const line of lines) {
    const text = line.replace(/\n$/, '');
    if (text === '') continue;
    if (text.startsWith('want ')) {
      const rest = text.slice(5);
      wants.push(rest.split(' ')[0] as string);
    } else if (text.startsWith('shallow ')) shallowReq.push(text.slice(8).trim());
    else if (text.startsWith('deepen ')) {
      const n = Number.parseInt(text.slice(7).trim(), 10);
      if (Number.isSafeInteger(n) && n > 0) depth = n;
    } else if (text.startsWith('have ')) {
      inSecondSection = true;
      haves.push(text.slice(5).trim());
    }
  }
  void inSecondSection;
  const cacheKey =
    'v0|' + wants.join(',') + '|' + haves.join(',') + '|' + shallowReq.join(',') + '|' + String(depth);
  const cached = repo.fetchCache.get(cacheKey);
  if (cached !== undefined) return cached;
  const plan = computeFetch(repo, wants, haves, depth, shallowReq);
  const pack = writePack(plan.objects);
  const parts: Buffer[] = [pktLine('NAK\n')];
  for (const oid of plan.shallow) parts.push(pktLine('shallow ' + oid + '\n'));
  for (const oid of plan.unshallow) parts.push(pktLine('unshallow ' + oid + '\n'));
  for (let off = 0; off < pack.length; off += 65515) {
    const chunk = pack.subarray(off, Math.min(pack.length, off + 65515));
    parts.push(pktLine(Buffer.concat([Buffer.from([1]), chunk])));
  }
  parts.push(PKT_FLUSH);
  const out = Buffer.concat(parts);
  repo.fetchCache.set(cacheKey, out);
  return out;
}

function handleUploadPack(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  owner: string,
  repoName: string,
  body: Buffer,
): void {
  const repo = getRepo(owner, repoName);
  if (repo === undefined) {
    sendRestError(res, 404, 'Not Found');
    return;
  }
  let packets: Pkt[];
  try {
    packets = decodeAllPktLines(body);
  } catch {
    sendRestError(res, 400, 'Bad pkt-line stream');
    return;
  }
  const lines = pktLinesToStrings(packets);
  const first = lines.length > 0 ? (lines[0] as string) : '';
  let out: Buffer;
  try {
    if (req.headers['git-protocol'] === 'version=2') {
      if (first.startsWith('command=ls-refs')) out = handleLsRefs(repo, lines);
      else if (first.startsWith('command=fetch')) out = handleFetchV2(repo, lines);
      else {
        sendRestError(res, 400, 'Unknown v2 command');
        return;
      }
    } else {
      out = handleFetchV0(repo, lines);
    }
  } catch {
    sendRestError(res, 400, 'Bad upload-pack request');
    return;
  }
  res.writeHead(200, {
    'content-type': 'application/x-git-upload-pack-result',
    ...gitRequestIdHeader(),
  });
  res.end(out);
}

interface PushCommand {
  oldOid: string;
  newOid: string;
  ref: string;
}

function handleReceivePack(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  owner: string,
  repoName: string,
  body: Buffer,
): void {
  const repo = getRepo(owner, repoName);
  if (repo === undefined) {
    sendRestError(res, 404, 'Not Found');
    return;
  }
  let decoded: { packets: Pkt[]; rest: number };
  try {
    decoded = decodePktLines(body);
  } catch {
    sendRestError(res, 400, 'Bad pkt-line stream');
    return;
  }
  const commands: PushCommand[] = [];
  for (const packet of decoded.packets) {
    if (packet.kind !== 'data' || packet.payload === null) continue;
    let text = packet.payload.toString('utf8');
    const nul = text.indexOf('\0');
    if (nul >= 0) text = text.slice(0, nul);
    const line = text.replace(/\n$/, '');
    const parts = line.split(' ');
    if (parts.length < 3) continue;
    commands.push({ oldOid: parts[0] as string, newOid: parts[1] as string, ref: parts[2] as string });
  }
  const packBytes = body.subarray(decoded.rest);
  let unpackOk = true;
  let unpackDetail = 'ok';
  if (packBytes.length > 0) {
    try {
      const objects = readPack(packBytes);
      for (const entry of objects) {
        repo.objects.set(entry[0], entry[1]);
      }
    } catch {
      unpackOk = false;
      unpackDetail = 'unpack error';
    }
  }
  const results: Array<{ ref: string; ok: boolean; reason: string }> = [];
  for (const command of commands) {
    if (!unpackOk) {
      results.push({ ref: command.ref, ok: false, reason: 'unpack failed' });
      continue;
    }
    if (!command.ref.startsWith('refs/')) {
      results.push({ ref: command.ref, ok: false, reason: 'invalid ref' });
      continue;
    }
    const current = repo.refs.get(command.ref);
    if (command.newOid === ZERO_OID) {
      // delete
      if (current !== undefined) repo.refs.delete(command.ref);
      results.push({ ref: command.ref, ok: true, reason: '' });
      continue;
    }
    const newObj = repo.objects.get(command.newOid);
    if (newObj === undefined) {
      results.push({ ref: command.ref, ok: false, reason: 'unable to process' });
      continue;
    }
    if (command.oldOid === ZERO_OID) {
      if (current !== undefined) {
        results.push({ ref: command.ref, ok: false, reason: 'already exists' });
        continue;
      }
      repo.refs.set(command.ref, command.newOid);
      results.push({ ref: command.ref, ok: true, reason: '' });
      continue;
    }
    if (current === undefined) {
      results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    if (current !== command.oldOid) {
      results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    const newCommit = peelToCommit(repo, command.newOid);
    const oldCommit = peelToCommit(repo, command.oldOid);
    if (!isAncestor(repo, oldCommit, newCommit)) {
      results.push({ ref: command.ref, ok: false, reason: 'non-fast-forward' });
      continue;
    }
    repo.refs.set(command.ref, command.newOid);
    results.push({ ref: command.ref, ok: true, reason: '' });
  }
  bumpRepo(repo);
  const inner: Buffer[] = [pktLine('unpack ' + unpackDetail + '\n')];
  for (const result of results) {
    inner.push(
      pktLine(result.ok ? 'ok ' + result.ref + '\n' : 'ng ' + result.ref + ' ' + result.reason + '\n'),
    );
  }
  const band = Buffer.concat([Buffer.from([1]), Buffer.concat(inner)]);
  const out = Buffer.concat([pktLine(band), PKT_FLUSH]);
  res.writeHead(200, {
    'content-type': 'application/x-git-receive-pack-result',
    ...gitRequestIdHeader(),
  });
  res.end(out);
}

// ------------------------------------------------------------------ GraphQL
// A small executor for the query/mutation subset the suite sends: fields,
// aliases, arguments (literals, variables, lists, input objects), inline
// fragments, named fragments, and __type introspection.

interface GqlSelection {
  kind: 'field' | 'fragment';
  name: string;
  alias: string | null;
  args: Record<string, unknown>;
  selections: GqlSelection[];
  typeCondition: string | null;
}

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  selections: GqlSelection[];
}

interface GqlToken {
  t: string;
  v: string;
}

function tokenizeGql(src: string): GqlToken[] {
  const tokens: GqlToken[] = [];
  let i = 0;
  while (i < src.length) {
    const ch = src[i] as string;
    if (ch === ' ' || ch === '\t' || ch === '\n' || ch === '\r' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && src.slice(i, i + 3) === '...') {
      tokens.push({ t: '...', v: '...' });
      i += 3;
      continue;
    }
    if ('{}():[]!=$@'.includes(ch)) {
      tokens.push({ t: ch, v: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let j = i + 1;
      let out = '';
      while (j < src.length && src[j] !== '"') {
        if (src[j] === '\\' && j + 1 < src.length) {
          const esc = src[j + 1] as string;
          if (esc === 'n') out += '\n';
          else if (esc === 't') out += '\t';
          else if (esc === 'r') out += '\r';
          else out += esc;
          j += 2;
        } else {
          out += src[j] as string;
          j += 1;
        }
      }
      tokens.push({ t: 'string', v: out });
      i = j + 1;
      continue;
    }
    if (/[0-9-]/.test(ch)) {
      let j = i;
      while (j < src.length && /[0-9.eE+-]/.test(src[j] as string)) j += 1;
      tokens.push({ t: 'number', v: src.slice(i, j) });
      i = j;
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let j = i;
      while (j < src.length && /[A-Za-z0-9_]/.test(src[j] as string)) j += 1;
      tokens.push({ t: 'name', v: src.slice(i, j) });
      i = j;
      continue;
    }
    i += 1;
  }
  return tokens;
}

class GqlParser {
  private tokens: GqlToken[];
  private pos = 0;
  private fragments = new Map<string, GqlSelection[]>();

  constructor(src: string) {
    this.tokens = tokenizeGql(src);
  }

  private peek(): GqlToken | undefined {
    return this.tokens[this.pos];
  }

  private next(): GqlToken {
    const token = this.tokens[this.pos] as GqlToken;
    this.pos += 1;
    return token;
  }

  private expect(type: string): GqlToken {
    const token = this.next();
    if (token.t !== type && token.v !== type) throw new Error('expected ' + type + ', got ' + token.v);
    return token;
  }

  private skipBalanced(open: string, close: string): void {
    let depth = 0;
    for (;;) {
      const token = this.next();
      if (token.t === open) depth += 1;
      else if (token.t === close) {
        depth -= 1;
        if (depth === 0) return;
      }
    }
  }

  private skipDirectives(): void {
    while (this.peek()?.t === '@') {
      this.next();
      this.next();
      if (this.peek()?.t === '(') this.skipBalanced('(', ')');
    }
  }

  parseDocument(): GqlOperation[] {
    const operations: GqlOperation[] = [];
    while (this.pos < this.tokens.length) {
      const token = this.peek() as GqlToken;
      if (token.t === '{') {
        operations.push({ kind: 'query', name: null, selections: this.parseSelections() });
      } else if (token.t === 'name' && (token.v === 'query' || token.v === 'mutation')) {
        const kind = token.v as 'query' | 'mutation';
        this.next();
        let name: string | null = null;
        if (this.peek()?.t === 'name') name = this.next().v;
        if (this.peek()?.t === '(') this.skipBalanced('(', ')');
        this.skipDirectives();
        operations.push({ kind, name, selections: this.parseSelections() });
      } else if (token.t === 'name' && token.v === 'fragment') {
        this.next();
        const fragName = this.next().v;
        this.expect('name'); // 'on'
        this.next(); // type name
        this.fragments.set(fragName, this.parseSelections());
      } else {
        this.next();
      }
    }
    return operations;
  }

  private parseSelections(): GqlSelection[] {
    this.expect('{');
    const out: GqlSelection[] = [];
    while (this.peek() !== undefined && this.peek()?.t !== '}') {
      out.push(this.parseSelection());
    }
    this.expect('}');
    return out;
  }

  private parseSelection(): GqlSelection {
    const token = this.peek() as GqlToken;
    if (token.t === '...') {
      this.next();
      const next = this.peek() as GqlToken;
      if (next.t === 'name' && next.v === 'on') {
        this.next();
        const typeCondition = this.next().v;
        this.skipDirectives();
        return {
          kind: 'fragment',
          name: '',
          alias: null,
          args: {},
          selections: this.parseSelections(),
          typeCondition,
        };
      }
      const fragName = this.next().v;
      this.skipDirectives();
      return {
        kind: 'fragment',
        name: '',
        alias: null,
        args: {},
        selections: this.fragments.get(fragName) ?? [],
        typeCondition: null,
      };
    }
    let name = this.next().v;
    let alias: string | null = null;
    if (this.peek()?.t === ':') {
      this.next();
      alias = name;
      name = this.next().v;
    }
    let args: Record<string, unknown> = {};
    if (this.peek()?.t === '(') args = this.parseArgs();
    this.skipDirectives();
    let selections: GqlSelection[] = [];
    if (this.peek()?.t === '{') selections = this.parseSelections();
    return { kind: 'field', name, alias, args, selections, typeCondition: null };
  }

  private parseArgs(): Record<string, unknown> {
    this.expect('(');
    const args: Record<string, unknown> = {};
    while (this.peek() !== undefined && this.peek()?.t !== ')') {
      const name = this.next().v;
      this.expect(':');
      args[name] = this.parseValue();
    }
    this.expect(')');
    return args;
  }

  private parseValue(): unknown {
    const token = this.next();
    if (token.t === '$') return { __var: this.next().v };
    if (token.t === 'string') return token.v;
    if (token.t === 'number') return Number(token.v);
    if (token.t === '[') {
      const out: unknown[] = [];
      while (this.peek() !== undefined && this.peek()?.t !== ']') out.push(this.parseValue());
      this.expect(']');
      return out;
    }
    if (token.t === '{') {
      const out: Record<string, unknown> = {};
      while (this.peek() !== undefined && this.peek()?.t !== '}') {
        const key = this.next().v;
        this.expect(':');
        out[key] = this.parseValue();
      }
      this.expect('}');
      return out;
    }
    if (token.t === 'name') {
      if (token.v === 'true') return true;
      if (token.v === 'false') return false;
      if (token.v === 'null') return null;
      return token.v;
    }
    throw new Error('unexpected value token ' + token.v);
  }
}

const gqlDocCache = new Map<string, GqlOperation[]>();

function parseGqlDocument(query: string): GqlOperation[] {
  const cached = gqlDocCache.get(query);
  if (cached !== undefined) return cached;
  const parsed = new GqlParser(query).parseDocument();
  if (gqlDocCache.size > 64) gqlDocCache.clear();
  gqlDocCache.set(query, parsed);
  return parsed;
}

function resolveGqlValue(value: unknown, variables: Record<string, unknown>): unknown {
  if (Array.isArray(value)) return value.map((v) => resolveGqlValue(v, variables));
  if (isRecord(value)) {
    if (typeof value.__var === 'string') {
      const found = variables[value.__var];
      return found === undefined ? null : found;
    }
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value)) out[key] = resolveGqlValue(value[key], variables);
    return out;
  }
  return value;
}

function resolveGqlArgs(args: Record<string, unknown>, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(args)) out[key] = resolveGqlValue(args[key], variables);
  return out;
}

// ------------------------------------------------------------------ GraphQL values

function repoValue(repo: Repo): Record<string, unknown> {
  return { __typename: 'Repository', _repo: repo };
}

function issueValue(repo: Repo, issue: Issue): Record<string, unknown> {
  return { __typename: 'Issue', _repo: repo, _issue: issue };
}

function pullValue(repo: Repo, pr: Pull): Record<string, unknown> {
  return { __typename: 'PullRequest', _repo: repo, _pr: pr };
}

function decodeGid(id: string): { kind: string; repoId: number; number: number } | null {
  try {
    const parts = b64uDecode(id).split(':');
    if (parts.length < 2) return null;
    return {
      kind: parts[0] as string,
      repoId: Number(parts[1]),
      number: parts.length > 2 ? Number(parts[2]) : 0,
    };
  } catch {
    return null;
  }
}

function decodeRepoId(id: string): Repo | undefined {
  const decoded = decodeGid(id);
  if (decoded === null || decoded.kind !== 'Repository') return undefined;
  return reposById.get(decoded.repoId);
}

const GQL_TYPE_FIELDS: Record<string, string[]> = {
  Issue: ['id', 'number', 'title', 'state', 'body', 'author', 'createdAt', 'updatedAt'],
  PullRequest: ['id', 'number', 'title', 'body', 'headRefName', 'baseRefName', 'mergeable', 'state', 'merged', 'files'],
  Repository: [
    'id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef',
    'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest',
    'description', 'url',
  ],
  SearchType: [],
};

const GQL_TYPE_ENUMS: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'MILESTONE', 'COMMIT'],
};

function introspectType(name: string): Record<string, unknown> | null {
  if (GQL_TYPE_FIELDS[name] === undefined && GQL_TYPE_ENUMS[name] === undefined) return null;
  return {
    __typename: '__Type',
    name,
    kind: GQL_TYPE_ENUMS[name] !== undefined ? 'ENUM' : 'OBJECT',
    fields: (GQL_TYPE_FIELDS[name] ?? []).map((n) => ({ __typename: '__Field', name: n, description: null })),
    enumValues: (GQL_TYPE_ENUMS[name] ?? []).map((n) => ({ __typename: '__EnumValue', name: n, description: null })),
  };
}

function paginateGql<T extends { number: number }>(
  items: T[],
  args: Record<string, unknown>,
  mapFn: (item: T) => unknown,
  typeName: string,
): Record<string, unknown> {
  const first = typeof args.first === 'number' ? args.first : items.length;
  let startIdx = 0;
  if (typeof args.after === 'string' && args.after !== '') {
    try {
      const decoded = b64uDecode(args.after);
      const n = Number(decoded.split(':')[1]);
      const idx = items.findIndex((item) => item.number === n);
      if (idx >= 0) startIdx = idx + 1;
    } catch {
      // a bad cursor starts from the beginning
    }
  }
  const page = items.slice(startIdx, startIdx + first);
  const hasNext = startIdx + page.length < items.length;
  const endCursor =
    page.length > 0 ? b64uEncode('cursor:' + String(page[page.length - 1]?.number ?? 0)) : null;
  const startCursor = page.length > 0 ? b64uEncode('cursor:' + String(page[0]?.number ?? 0)) : null;
  return {
    __typename: typeName,
    nodes: page.map(mapFn),
    totalCount: items.length,
    pageInfo: {
      __typename: 'PageInfo',
      hasNextPage: hasNext,
      endCursor,
      hasPreviousPage: startIdx > 0,
      startCursor,
    },
  };
}

function issueConnection(repo: Repo, args: Record<string, unknown>): Record<string, unknown> {
  let list = [...repo.issues.values()];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const want = new Set(states.map((s) => String(s).toLowerCase()));
    list = list.filter((i) => want.has(i.state));
  } else {
    list = list.filter((i) => i.state === 'open');
  }
  const orderBy = isRecord(args.orderBy) ? args.orderBy : null;
  const dir = orderBy !== null && orderBy.direction === 'ASC' ? 1 : -1;
  list.sort((a, b) => (a.number - b.number) * dir);
  return paginateGql(list, args, (item) => issueValue(repo, item), 'IssueConnection');
}

function pullConnection(repo: Repo, args: Record<string, unknown>): Record<string, unknown> {
  let list = [...repo.pulls.values()];
  const states = args.states;
  if (Array.isArray(states) && states.length > 0) {
    const want = new Set(states.map((s) => String(s)));
    list = list.filter((p) => {
      const state = p.merged ? 'MERGED' : p.state === 'closed' ? 'CLOSED' : 'OPEN';
      return want.has(state);
    });
  } else {
    list = list.filter((p) => p.state === 'open');
  }
  list.sort((a, b) => b.number - a.number);
  return paginateGql(list, args, (item) => pullValue(repo, item), 'PullRequestConnection');
}

type GqlResolver = (parent: Record<string, unknown>, args: Record<string, unknown>) => unknown;

const GQL_RESOLVERS: Record<string, Record<string, GqlResolver>> = {
  Query: {
    viewer: () => ({ __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID }),
    repository: (_p, args) => {
      const repo = getRepo(String(args.owner ?? ''), String(args.name ?? ''));
      return repo === undefined ? null : repoValue(repo);
    },
    node: (_p, args) => {
      const decoded = decodeGid(String(args.id ?? ''));
      if (decoded === null) return null;
      if (decoded.kind === 'Repository') {
        const repo = reposById.get(decoded.repoId);
        return repo === undefined ? null : repoValue(repo);
      }
      if (decoded.kind === 'Issue') {
        const repo = reposById.get(decoded.repoId);
        const issue = repo?.issues.get(decoded.number);
        return issue === undefined || repo === undefined ? null : issueValue(repo, issue);
      }
      if (decoded.kind === 'PullRequest') {
        const repo = reposById.get(decoded.repoId);
        const pr = repo?.pulls.get(decoded.number);
        return pr === undefined || repo === undefined ? null : pullValue(repo, pr);
      }
      return null;
    },
    __type: (_p, args) => introspectType(String(args.name ?? '')),
  },
  User: {
    login: (parent) => parent.login ?? VIEWER_LOGIN,
  },
  Repository: {
    id: (parent) => b64uEncode('Repository:' + String((parent._repo as Repo).id)),
    databaseId: (parent) => (parent._repo as Repo).id,
    name: (parent) => (parent._repo as Repo).name,
    nameWithOwner: (parent) => (parent._repo as Repo).owner + '/' + (parent._repo as Repo).name,
    owner: () => ({ __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID }),
    defaultBranchRef: (parent) => {
      const repo = parent._repo as Repo;
      return repo.refs.has('refs/heads/' + repo.defaultBranch)
        ? { __typename: 'Ref', name: repo.defaultBranch }
        : null;
    },
    viewerPermission: () => 'ADMIN',
    hasIssuesEnabled: () => true,
    issue: (parent, args) => {
      const repo = parent._repo as Repo;
      const issue = repo.issues.get(Number(args.number));
      return issue === undefined ? null : issueValue(repo, issue);
    },
    issues: (parent, args) => issueConnection(parent._repo as Repo, args),
    pullRequests: (parent, args) => pullConnection(parent._repo as Repo, args),
    pullRequest: (parent, args) => {
      const repo = parent._repo as Repo;
      const pr = repo.pulls.get(Number(args.number));
      return pr === undefined ? null : pullValue(repo, pr);
    },
  },
  Ref: {
    name: (parent) => parent.name ?? null,
  },
  Issue: {
    id: (parent) => {
      const repo = parent._repo as Repo;
      const issue = parent._issue as Issue;
      return b64uEncode('Issue:' + repo.id + ':' + issue.number);
    },
    number: (parent) => (parent._issue as Issue).number,
    title: (parent) => (parent._issue as Issue).title,
    state: (parent) => ((parent._issue as Issue).state === 'open' ? 'OPEN' : 'CLOSED'),
    body: (parent) => (parent._issue as Issue).body,
  },
  IssueConnection: {
    nodes: (parent) => parent.nodes ?? [],
    pageInfo: (parent) => parent.pageInfo ?? null,
    totalCount: (parent) => parent.totalCount ?? 0,
  },
  PullRequest: {
    id: (parent) => {
      const repo = parent._repo as Repo;
      const pr = parent._pr as Pull;
      return b64uEncode('PullRequest:' + repo.id + ':' + pr.number);
    },
    number: (parent) => (parent._pr as Pull).number,
    title: (parent) => (parent._pr as Pull).title,
    body: (parent) => (parent._pr as Pull).body,
    headRefName: (parent) => (parent._pr as Pull).headRef,
    baseRefName: (parent) => (parent._pr as Pull).baseRef,
    mergeable: (parent) => {
      const repo = parent._repo as Repo;
      const pr = parent._pr as Pull;
      if (
        repo.refs.get('refs/heads/' + pr.headRef) === undefined ||
        repo.refs.get('refs/heads/' + pr.baseRef) === undefined
      ) {
        return 'UNKNOWN';
      }
      return prHasConflict(repo, pr) ? 'CONFLICTING' : 'MERGEABLE';
    },
    state: (parent) => {
      const pr = parent._pr as Pull;
      if (pr.merged) return 'MERGED';
      return pr.state === 'open' ? 'OPEN' : 'CLOSED';
    },
    merged: (parent) => (parent._pr as Pull).merged,
    files: (parent, args) => {
      const repo = parent._repo as Repo;
      const pr = parent._pr as Pull;
      const files = diffPullFiles(repo, pr.baseSha, pr.headSha);
      const first = typeof args.first === 'number' ? args.first : files.length;
      const page = files.slice(0, first);
      return {
        __typename: 'PullRequestFileConnection',
        nodes: page.map((f) => ({ __typename: 'PullRequestFile', path: f.filename })),
        pageInfo: {
          __typename: 'PageInfo',
          hasNextPage: files.length > page.length,
          endCursor: page.length > 0 ? b64uEncode('cursor:' + String(page.length)) : null,
          hasPreviousPage: false,
          startCursor: null,
        },
      };
    },
  },
  PullRequestConnection: {
    nodes: (parent) => parent.nodes ?? [],
    pageInfo: (parent) => parent.pageInfo ?? null,
    totalCount: (parent) => parent.totalCount ?? 0,
  },
  PullRequestFileConnection: {
    nodes: (parent) => parent.nodes ?? [],
    pageInfo: (parent) => parent.pageInfo ?? null,
  },
  PullRequestFile: {
    path: (parent) => parent.path ?? null,
  },
  PageInfo: {
    hasNextPage: (parent) => parent.hasNextPage ?? false,
    endCursor: (parent) => parent.endCursor ?? null,
    hasPreviousPage: (parent) => parent.hasPreviousPage ?? false,
    startCursor: (parent) => parent.startCursor ?? null,
  },
  CreateIssuePayload: {
    issue: (parent) => parent.issue ?? null,
  },
  CloseIssuePayload: {
    issue: (parent) => parent.issue ?? null,
  },
  CreatePullRequestPayload: {
    pullRequest: (parent) => parent.pullRequest ?? null,
  },
  MergePullRequestPayload: {
    pullRequest: (parent) => parent.pullRequest ?? null,
  },
  AddCommentPayload: {
    commentEdge: (parent) => parent.commentEdge ?? null,
  },
  IssueCommentEdge: {
    node: (parent) => parent.node ?? null,
    cursor: (parent) => parent.cursor ?? null,
  },
  IssueComment: {
    id: (parent) => parent.id ?? null,
    body: (parent) => parent.body ?? null,
  },
  __Type: {
    name: (parent) => parent.name ?? null,
    kind: (parent) => parent.kind ?? null,
    fields: (parent) => parent.fields ?? [],
    enumValues: (parent) => parent.enumValues ?? [],
  },
  __Field: {
    name: (parent) => parent.name ?? null,
    description: (parent) => parent.description ?? null,
  },
  __EnumValue: {
    name: (parent) => parent.name ?? null,
    description: (parent) => parent.description ?? null,
  },
  Mutation: {
    createIssue: (_p, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const repo = decodeRepoId(String(input.repositoryId ?? ''));
      if (repo === undefined) throw new Error('repository not found');
      const issue: Issue = {
        id: ++entitySeq,
        number: repo.nextNumber++,
        repoId: repo.id,
        title: String(input.title ?? ''),
        body: String(input.body ?? ''),
        state: 'open',
        labels: [],
        comments: [],
        _json: null,
      };
      repo.issues.set(issue.number, issue);
      return { __typename: 'CreateIssuePayload', issue: issueValue(repo, issue) };
    },
    closeIssue: (_p, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const decoded = decodeGid(String(input.issueId ?? ''));
      const repo = decoded !== null ? reposById.get(decoded.repoId) : undefined;
      const issue = decoded !== null && repo !== undefined ? repo.issues.get(decoded.number) : undefined;
      if (issue === undefined || repo === undefined) throw new Error('issue not found');
      issue.state = 'closed';
      issue._json = null;
      return { __typename: 'CloseIssuePayload', issue: issueValue(repo, issue) };
    },
    createPullRequest: (_p, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const repo = decodeRepoId(String(input.repositoryId ?? ''));
      if (repo === undefined) throw new Error('repository not found');
      const head = String(input.headRefName ?? '');
      const base = String(input.baseRefName ?? '');
      const headSha = repo.refs.get('refs/heads/' + head);
      const baseSha = repo.refs.get('refs/heads/' + base);
      if (headSha === undefined || baseSha === undefined) {
        throw new Error('head or base branch does not exist');
      }
      for (const existing of repo.pulls.values()) {
        if (existing.state === 'open' && existing.headRef === head && existing.baseRef === base) {
          throw new Error('a pull request for this head already exists');
        }
      }
      const pr: Pull = {
        id: ++entitySeq,
        number: repo.nextNumber++,
        repoId: repo.id,
        title: String(input.title ?? ''),
        body: String(input.body ?? ''),
        state: 'open',
        merged: false,
        mergedAt: '',
        mergeCommitSha: '',
        headRef: head,
        baseRef: base,
        headSha,
        baseSha,
      };
      repo.pulls.set(pr.number, pr);
      return { __typename: 'CreatePullRequestPayload', pullRequest: pullValue(repo, pr) };
    },
    mergePullRequest: (_p, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const decoded = decodeGid(String(input.pullRequestId ?? ''));
      const repo = decoded !== null ? reposById.get(decoded.repoId) : undefined;
      const pr = decoded !== null && repo !== undefined ? repo.pulls.get(decoded.number) : undefined;
      if (pr === undefined || repo === undefined) throw new Error('pull request not found');
      if (pr.merged) throw new Error('pull request already merged');
      const sha = mergePull(repo, pr);
      if (sha === null) throw new Error('Merge conflict');
      return { __typename: 'MergePullRequestPayload', pullRequest: pullValue(repo, pr) };
    },
    addComment: (_p, args) => {
      const input = isRecord(args.input) ? args.input : {};
      const decoded = decodeGid(String(input.subjectId ?? ''));
      const repo = decoded !== null ? reposById.get(decoded.repoId) : undefined;
      const issue = decoded !== null && repo !== undefined ? repo.issues.get(decoded.number) : undefined;
      if (issue === undefined || repo === undefined) throw new Error('issue not found');
      const comment: Comment = { id: ++entitySeq, body: String(input.body ?? '') };
      issue.comments.push(comment);
      issue._json = null;
      return {
        __typename: 'AddCommentPayload',
        commentEdge: {
          __typename: 'IssueCommentEdge',
          node: {
            __typename: 'IssueComment',
            id: b64uEncode('IssueComment:' + repo.id + ':' + comment.id),
            body: comment.body,
          },
          cursor: b64uEncode('cursor:' + comment.id),
        },
      };
    },
  },
};

const GQL_FIELD_TYPES: Record<string, Record<string, string>> = {
  Query: { viewer: 'User', repository: 'Repository', node: 'Node', __type: '__Type' },
  Mutation: {
    createIssue: 'CreateIssuePayload',
    closeIssue: 'CloseIssuePayload',
    createPullRequest: 'CreatePullRequestPayload',
    mergePullRequest: 'MergePullRequestPayload',
    addComment: 'AddCommentPayload',
  },
  User: { login: 'String' },
  Repository: {
    id: 'ID',
    databaseId: 'Int',
    name: 'String',
    nameWithOwner: 'String',
    owner: 'User',
    defaultBranchRef: 'Ref',
    viewerPermission: 'String',
    hasIssuesEnabled: 'Boolean',
    issue: 'Issue',
    issues: 'IssueConnection',
    pullRequests: 'PullRequestConnection',
    pullRequest: 'PullRequest',
  },
  Ref: { name: 'String' },
  Issue: { id: 'ID', number: 'Int', title: 'String', state: 'String', body: 'String' },
  IssueConnection: { nodes: 'Issue[]', pageInfo: 'PageInfo', totalCount: 'Int' },
  PullRequest: {
    id: 'ID',
    number: 'Int',
    title: 'String',
    body: 'String',
    headRefName: 'String',
    baseRefName: 'String',
    mergeable: 'String',
    state: 'String',
    merged: 'Boolean',
    files: 'PullRequestFileConnection',
  },
  PullRequestConnection: { nodes: 'PullRequest[]', pageInfo: 'PageInfo', totalCount: 'Int' },
  PullRequestFileConnection: { nodes: 'PullRequestFile[]', pageInfo: 'PageInfo' },
  PullRequestFile: { path: 'String' },
  PageInfo: { hasNextPage: 'Boolean', endCursor: 'String', hasPreviousPage: 'Boolean', startCursor: 'String' },
  CreateIssuePayload: { issue: 'Issue' },
  CloseIssuePayload: { issue: 'Issue' },
  CreatePullRequestPayload: { pullRequest: 'PullRequest' },
  MergePullRequestPayload: { pullRequest: 'PullRequest' },
  AddCommentPayload: { commentEdge: 'IssueCommentEdge' },
  IssueCommentEdge: { node: 'IssueComment', cursor: 'String' },
  IssueComment: { id: 'ID', body: 'String' },
  __Type: { name: 'String', kind: 'String', fields: '__Field[]', enumValues: '__EnumValue[]' },
  __Field: { name: 'String', description: 'String' },
  __EnumValue: { name: 'String', description: 'String' },
};

function applyGqlSelections(
  retType: string | undefined,
  value: unknown,
  selections: GqlSelection[],
  errors: Array<{ message: string }>,
  variables: Record<string, unknown>,
): unknown {
  if (value === null || value === undefined) return null;
  if (retType === undefined) return value;
  if (retType.endsWith('[]')) {
    const elem = retType.slice(0, -2);
    if (!Array.isArray(value)) return value;
    return value.map((el) => applyGqlSelections(elem, el, selections, errors, variables));
  }
  if (
    retType === 'String' ||
    retType === 'Int' ||
    retType === 'Float' ||
    retType === 'Boolean' ||
    retType === 'ID'
  ) {
    return value;
  }
  if (selections.length === 0) return value;
  const typeName =
    isRecord(value) && typeof value.__typename === 'string' ? value.__typename : retType;
  return execGqlSelections(typeName, value, selections, errors, variables);
}

function execGqlSelections(
  typeName: string,
  value: unknown,
  selections: GqlSelection[],
  errors: Array<{ message: string }>,
  variables: Record<string, unknown>,
): Record<string, unknown> | null {
  if (value === null || value === undefined) return null;
  const out: Record<string, unknown> = {};
  for (const sel of selections) {
    if (sel.kind === 'fragment') {
      const valueType = isRecord(value) && typeof value.__typename === 'string' ? value.__typename : typeName;
      if (sel.typeCondition !== null && sel.typeCondition !== typeName && sel.typeCondition !== valueType) {
        continue;
      }
      const sub = execGqlSelections(typeName, value, sel.selections, errors, variables);
      if (sub !== null) Object.assign(out, sub);
      continue;
    }
    const key = sel.alias ?? sel.name;
    if (sel.name === '__typename') {
      out[key] =
        isRecord(value) && typeof value.__typename === 'string' ? value.__typename : typeName;
      continue;
    }
    const resolver = GQL_RESOLVERS[typeName]?.[sel.name];
    if (resolver === undefined) {
      errors.push({ message: 'Cannot query field "' + sel.name + '" on type "' + typeName + '".' });
      out[key] = null;
      continue;
    }
    const args = resolveGqlArgs(sel.args, variables);
    let resolved: unknown;
    try {
      resolved = resolver(value as Record<string, unknown>, args);
    } catch (err) {
      errors.push({ message: err instanceof Error ? err.message : String(err) });
      out[key] = null;
      continue;
    }
    const retType = GQL_FIELD_TYPES[typeName]?.[sel.name];
    out[key] = applyGqlSelections(retType, resolved, sel.selections, errors, variables);
  }
  return out;
}

function executeGql(
  query: string,
  variables: Record<string, unknown>,
  operationName: string | null,
): Record<string, unknown> {
  const operations = parseGqlDocument(query);
  let operation = operations[0];
  if (operationName !== null) {
    const named = operations.find((op) => op.name === operationName);
    if (named !== undefined) operation = named;
  }
  if (operation === undefined) {
    return { data: null, errors: [{ message: 'No operation in document' }] };
  }
  const errors: Array<{ message: string }> = [];
  const rootType = operation.kind === 'mutation' ? 'Mutation' : 'Query';
  const data = execGqlSelections(rootType, {}, operation.selections, errors, variables);
  const result: Record<string, unknown> = { data };
  if (errors.length > 0) result.errors = errors;
  return result;
}

function executeGqlOp(op: unknown): Record<string, unknown> {
  if (!isRecord(op) || typeof op.query !== 'string') {
    return { data: null, errors: [{ message: 'Invalid GraphQL operation' }] };
  }
  const variables = isRecord(op.variables) ? (op.variables as Record<string, unknown>) : {};
  try {
    return executeGql(
      op.query,
      variables,
      typeof op.operationName === 'string' ? op.operationName : null,
    );
  } catch (err) {
    return { data: null, errors: [{ message: err instanceof Error ? err.message : String(err) }] };
  }
}

async function handleGraphql(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  if (!isAuthed(req)) {
    sendRestError(res, 401, 'Requires authentication');
    return;
  }
  let body: unknown;
  try {
    body = parseJsonBody(await readBody(req));
  } catch {
    sendRestError(res, 400, 'Invalid JSON');
    return;
  }
  if (Array.isArray(body)) {
    sendJson(res, 200, body.map((op) => executeGqlOp(op)));
  } else {
    sendJson(res, 200, executeGqlOp(body));
  }
}

// ------------------------------------------------------------------ MCP

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

/** Built once: two tools/list calls must answer the same list byte for byte. */
const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Repository name' },
        owner: { type: 'string', description: 'Owner login' },
        description: { type: 'string', description: 'Repository description' },
        private: { type: 'boolean', description: 'Whether the repository is private' },
      },
      required: ['name'],
    },
  },
  {
    name: 'get_repo',
    description: 'Get a repository by owner and name.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        full_name: { type: 'string', description: 'owner/repo' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_issue',
    description: 'Create an issue in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Issue title' },
        body: { type: 'string', description: 'Issue body' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List issues in a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        state: { type: 'string', description: 'open, closed or all' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Create a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        title: { type: 'string', description: 'Pull request title' },
        body: { type: 'string', description: 'Pull request body' },
        head: { type: 'string', description: 'Head branch name' },
        base: { type: 'string', description: 'Base branch name' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'Owner login' },
        repo: { type: 'string', description: 'Repository name' },
        pull_number: { type: 'integer', description: 'Pull request number' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function resolveMcpRepo(args: Record<string, unknown>): Repo | undefined {
  let owner = typeof args.owner === 'string' ? args.owner : '';
  let repoName = typeof args.repo === 'string' ? args.repo : '';
  if ((owner === '' || repoName === '') && typeof args.full_name === 'string') {
    const parts = (args.full_name as string).split('/');
    if (parts.length === 2) {
      owner = parts[0] as string;
      repoName = parts[1] as string;
    }
  }
  if (owner === '') owner = VIEWER_LOGIN;
  return getRepo(owner, repoName);
}

function runMcpTool(name: string, args: Record<string, unknown>): unknown {
  switch (name) {
    case 'create_repo': {
      const repoName = String(args.name ?? '');
      if (repoName === '') throw new Error('name is required');
      if (reposByName.has(repoName)) throw new Error('name already exists on this account');
      const repo = createRepo(
        repoName,
        args.private === true,
        typeof args.description === 'string' ? args.description : '',
      );
      return repoJson(repo);
    }
    case 'get_repo': {
      const repo = resolveMcpRepo(args);
      if (repo === undefined) throw new Error('repository not found');
      return repoJson(repo);
    }
    case 'create_issue': {
      const repo = resolveMcpRepo(args);
      if (repo === undefined) throw new Error('repository not found');
      const title = String(args.title ?? '');
      if (title === '') throw new Error('title is required');
      const issue: Issue = {
        id: ++entitySeq,
        number: repo.nextNumber++,
        repoId: repo.id,
        title,
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        labels: [],
        comments: [],
        _json: null,
      };
      repo.issues.set(issue.number, issue);
      return issueJson(issue);
    }
    case 'list_issues': {
      const repo = resolveMcpRepo(args);
      if (repo === undefined) throw new Error('repository not found');
      const state = typeof args.state === 'string' ? args.state : 'open';
      let list = [...repo.issues.values()];
      if (state === 'open') list = list.filter((i) => i.state === 'open');
      else if (state === 'closed') list = list.filter((i) => i.state === 'closed');
      list.sort((a, b) => b.number - a.number);
      return list.map((i) => issueJson(i));
    }
    case 'create_pull_request': {
      const repo = resolveMcpRepo(args);
      if (repo === undefined) throw new Error('repository not found');
      const head = String(args.head ?? '');
      const base = String(args.base ?? '');
      const headSha = repo.refs.get('refs/heads/' + head);
      const baseSha = repo.refs.get('refs/heads/' + base);
      if (headSha === undefined || baseSha === undefined) {
        throw new Error('head or base branch does not exist');
      }
      for (const existing of repo.pulls.values()) {
        if (existing.state === 'open' && existing.headRef === head && existing.baseRef === base) {
          throw new Error('a pull request for this head already exists');
        }
      }
      const pr: Pull = {
        id: ++entitySeq,
        number: repo.nextNumber++,
        repoId: repo.id,
        title: String(args.title ?? ''),
        body: typeof args.body === 'string' ? args.body : '',
        state: 'open',
        merged: false,
        mergedAt: '',
        mergeCommitSha: '',
        headRef: head,
        baseRef: base,
        headSha,
        baseSha,
      };
      repo.pulls.set(pr.number, pr);
      return pullJson(pr);
    }
    case 'merge_pull_request': {
      const repo = resolveMcpRepo(args);
      if (repo === undefined) throw new Error('repository not found');
      const num = typeof args.pull_number === 'number' ? args.pull_number : Number(args.pull_number);
      const pr = repo.pulls.get(num);
      if (pr === undefined) throw new Error('pull request not found');
      if (pr.merged) throw new Error('pull request already merged');
      const sha = mergePull(repo, pr);
      if (sha === null) throw new Error('Merge conflict');
      return pullJson(pr);
    }
    default:
      throw new Error('Unknown tool: ' + name);
  }
}

async function handleMcp(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  if (req.method === 'DELETE') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end('{}');
    return;
  }
  if (req.method !== 'POST') {
    res.writeHead(405, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'method not allowed' }));
    return;
  }
  if (!isAuthed(req)) {
    res.writeHead(401, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32001, message: 'Unauthorized' },
      }),
    );
    return;
  }
  const raw = await readBody(req);
  let msg: unknown;
  try {
    msg = JSON.parse(raw.toString('utf8'));
  } catch {
    res.writeHead(400, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        jsonrpc: '2.0',
        id: null,
        error: { code: -32700, message: 'Parse error' },
      }),
    );
    return;
  }
  if (!isRecord(msg) || typeof msg.method !== 'string') {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        jsonrpc: '2.0',
        id: isRecord(msg) ? (msg.id ?? null) : null,
        error: { code: -32600, message: 'Invalid Request' },
      }),
    );
    return;
  }
  const id = msg.id ?? null;
  const isNotification = msg.id === undefined;
  const reply = (result: unknown): void => {
    if (isNotification) {
      res.writeHead(202, { 'content-type': 'application/json' });
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
  };
  const replyError = (code: number, message: string): void => {
    if (isNotification) {
      res.writeHead(202, { 'content-type': 'application/json' });
      res.end();
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ jsonrpc: '2.0', id, error: { code, message } }));
  };
  switch (msg.method) {
    case 'server/discover':
      reply({
        resultType: 'discover',
        supportedVersions: ['2026-07-28', '2025-11-25', '2025-06-18'],
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'github-core-clone', version: '1.0.0' },
        _meta: {
          'io.modelcontextprotocol/serverInfo': { name: 'github-core-clone', version: '1.0.0' },
        },
        instructions: 'A GitHub-compatible git forge: repositories, issues, pull requests, git smart HTTP.',
      });
      return;
    case 'initialize': {
      const params = isRecord(msg.params) ? msg.params : {};
      const offered = typeof params.protocolVersion === 'string' ? params.protocolVersion : '2025-11-25';
      const supported = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
      reply({
        protocolVersion: supported.includes(offered) ? offered : '2025-11-25',
        capabilities: { tools: {} },
        serverInfo: { name: 'github-core-clone', version: '1.0.0' },
      });
      return;
    }
    case 'notifications/initialized':
    case 'notifications/cancelled':
      res.writeHead(202, { 'content-type': 'application/json' });
      res.end();
      return;
    case 'tools/list':
      reply({ tools: MCP_TOOLS });
      return;
    case 'tools/call': {
      const params = isRecord(msg.params) ? msg.params : {};
      const toolName = typeof params.name === 'string' ? params.name : '';
      const args = isRecord(params.arguments) ? (params.arguments as Record<string, unknown>) : {};
      const tool = MCP_TOOLS.find((t) => t.name === toolName);
      if (tool === undefined) {
        replyError(-32602, 'Unknown tool: ' + toolName);
        return;
      }
      const required = Array.isArray(tool.inputSchema.required)
        ? (tool.inputSchema.required as string[])
        : [];
      const missing = required.filter((key) => args[key] === undefined || args[key] === null);
      if (missing.length > 0) {
        replyError(-32602, 'Missing required argument: ' + missing.join(', '));
        return;
      }
      try {
        const result = runMcpTool(toolName, args);
        reply({
          content: [{ type: 'text', text: JSON.stringify(result) }],
          structuredContent: result,
          isError: false,
        });
      } catch (err) {
        reply({
          content: [
            {
              type: 'text',
              text: 'Error: ' + (err instanceof Error ? err.message : String(err)),
            },
          ],
          isError: true,
        });
      }
      return;
    }
    case 'ping':
      reply({});
      return;
    default:
      replyError(-32601, 'Method not found: ' + msg.method);
      return;
  }
}

// ------------------------------------------------------------------ dispatch

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

async function handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
  const method = req.method ?? 'GET';
  const rawUrl = req.url ?? '/';
  let url: URL;
  try {
    url = new URL(rawUrl, 'http://127.0.0.1');
  } catch {
    sendRestError(res, 400, 'Bad URL');
    return;
  }
  const path = url.pathname;
  const query = url.searchParams;
  const segments = path.split('/').filter((s) => s !== '');

  if (path === '/healthz') {
    if (method !== 'GET') {
      sendRestError(res, 404, 'Not Found');
      return;
    }
    sendJson(res, 200, { ok: true });
    return;
  }

  // git smart HTTP: /{owner}/{repo}.git/...
  if (segments.length >= 3 && (segments[1] as string).endsWith('.git')) {
    const owner = safeDecode(segments[0] as string);
    const repoName = safeDecode((segments[1] as string).slice(0, -4));
    if (segments[2] === 'info' && segments[3] === 'refs' && method === 'GET') {
      const service = query.get('service') ?? '';
      if (service !== 'git-upload-pack' && service !== 'git-receive-pack') {
        sendRestError(res, 404, 'Not Found');
        return;
      }
      handleInfoRefs(req, res, owner, repoName, service);
      return;
    }
    if (segments[2] === 'git-upload-pack' && method === 'POST') {
      const body = await readBody(req);
      handleUploadPack(req, res, owner, repoName, body);
      return;
    }
    if (segments[2] === 'git-receive-pack' && method === 'POST') {
      const body = await readBody(req);
      handleReceivePack(req, res, owner, repoName, body);
      return;
    }
    sendRestError(res, 404, 'Not Found');
    return;
  }

  if (segments.length === 2 && segments[0] === 'api' && segments[1] === 'graphql') {
    if (method !== 'POST') {
      sendRestError(res, 404, 'Not Found');
      return;
    }
    await handleGraphql(req, res);
    return;
  }

  if (segments.length === 1 && segments[0] === 'mcp') {
    await handleMcp(req, res);
    return;
  }

  if (segments.length >= 2 && segments[0] === 'api' && segments[1] === 'v3') {
    await handleRest(req, res, segments, query, path);
    return;
  }

  sendRestError(res, 404, 'Not Found');
}

// ------------------------------------------------------------------ lifecycle

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function registerAndPoll(envUrl: string, port: number): Promise<void> {
  const base = envUrl.replace(/\/+$/, '');
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      const response = await fetch(base + '/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ port }),
      });
      if (response.ok) break;
    } catch {
      // the env may not be listening yet; retry
    }
    await sleep(500);
  }
  for (;;) {
    try {
      const response = await fetch(base + '/done');
      if (response.ok) {
        const data = (await response.json()) as { done?: boolean };
        if (data !== null && data.done === true) {
          server.close();
          process.exit(0);
        }
      }
    } catch {
      // transient; keep polling
    }
    await sleep(200);
  }
}

const server = http.createServer((req, res) => {
  void handleRequest(req, res).catch((err) => {
    process.stderr.write(
      'handler error: ' + (err instanceof Error ? (err.stack ?? err.message) : String(err)) + '\n',
    );
    try {
      if (!res.headersSent) sendJson(res, 500, { message: 'Internal error' });
      else res.end();
    } catch {
      // the client is gone; nothing to do
    }
  });
});
server.keepAliveTimeout = 30000;

const envUrl = process.env.MAKEFUN_ENV_URL ?? '';
server.listen(0, '127.0.0.1', () => {
  const address = server.address();
  const port = typeof address === 'object' && address !== null ? address.port : 0;
  process.stderr.write('github-core-clone listening on 127.0.0.1:' + port + '\n');
  if (envUrl !== '') {
    void registerAndPoll(envUrl, port);
  }
});
