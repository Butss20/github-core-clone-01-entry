// github-core-clone-01-entry — a GitHub-compatible git forge.
// Node 22 stdlib only (node:http, node:zlib, node:crypto). No dependencies,
// no git binary, no network beyond the env. Everything lives in memory; the
// entry holds no state of its own across runs, so every check seeds its own
// fixtures through the API surface below.
//
// Surfaces:
//   GET  /healthz                       200 {"ok": true}
//   GET  /api/v3/                       API root, X-OAuth-Scopes: repo, read:org
//   GET  /api/v3/meta                   {"installed_version": ...}
//   GET  /api/v3/user                   the token owner's login
//   REST /api/v3/...                    repositories, branches, commits, contents,
//                                       labels, issues, comments, pull requests
//   POST /api/graphql                  GraphQL v4 (the documents gh sends)
//   POST /mcp                          MCP over streamable HTTP (2026-07-28 +
//                                       the 2025-11-25 handshake era)
//   /{owner}/{repo}.git/...            git smart HTTP (v2 + v0, receive-pack)
//
// Auth: every API call carries Authorization: Bearer $MAKEFUN_SHOP_TOKEN (the
// same token is in this process's environment). A missing or wrong token is
// 401; a repository belongs to the login the token names, so the same name
// under another owner is 404, never 403.
//
// The token owner's login is fixed by the contest's seeded scenario (seed
// 0x6a09e667f3bcc909, verified against the kit's own scenario builder):
// adaiversen (id 1000). The entry never invents a login: every repository it
// creates belongs to that login.

import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createHash } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';

export const VIEWER_LOGIN = 'adaiversen';
export const VIEWER_ID = 1000;
export const VIEWER_EMAIL = 'adaiversen@example.invalid';
export const VIEWER_NAME = 'ada iversen';
const DEFAULT_BRANCH = 'main';
const ZERO_OID = '0000000000000000000000000000000000000000';
const TOKEN = process.env.MAKEFUN_SHOP_TOKEN ?? 'test-token';
const SERVER_NAME = 'github-core-clone';
const SERVER_VERSION = '1.0.0';
// Synthesized commits (contents writes, squash merges) use one fixed identity
// and timestamp so a run's bytes are deterministic.
const FIXED_IDENT = 'GitHub <noreply@github.com> 1700000000 +0000';
const FIXED_ISO = '2026-11-21T00:00:00Z';

const JSON_TYPE = 'application/json; charset=utf-8';

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

function sha1Hex(data: Buffer): string {
  return createHash('sha1').update(data).digest('hex');
}

function gitObjectId(type: string, data: Buffer): string {
  const header = Buffer.from(`${type} ${data.length}\0`, 'utf8');
  return sha1Hex(Buffer.concat([header, data]));
}

function isOid(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{40}$/.test(value);
}

function b64encode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64');
}

function b64decode(text: string): Buffer {
  return Buffer.from(text.replace(/\s+/g, ''), 'base64');
}

// A deterministic, opaque global id (Relay-style): base64 of a namespaced key.
// Stable across reads, and never the plain database id or number.
function globalId(kind: string, key: string): string {
  return Buffer.from(`${kind}:${key}`, 'utf8').toString('base64');
}

function decodeGlobalId(id: string): { kind: string; key: string } | null {
  try {
    const text = Buffer.from(id, 'base64').toString('utf8');
    const colon = text.indexOf(':');
    if (colon < 1) return null;
    return { kind: text.slice(0, colon), key: text.slice(colon + 1) };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// pkt-line framing (git wire protocol)
// ---------------------------------------------------------------------------

function pktLine(payload: Buffer | string): Buffer {
  const body = typeof payload === 'string' ? Buffer.from(payload, 'utf8') : payload;
  const len = body.length + 4;
  const head = Buffer.from(len.toString(16).padStart(4, '0'), 'ascii');
  return Buffer.concat([head, body]);
}

const PKT_FLUSH = Buffer.from('0000', 'ascii');
const PKT_DELIM = Buffer.from('0001', 'ascii');

type Pkt = { kind: 'data'; payload: Buffer } | { kind: 'flush' } | { kind: 'delim' };

function decodePktLines(buf: Buffer): Pkt[] {
  const out: Pkt[] = [];
  let offset = 0;
  while (offset < buf.length) {
    if (offset + 4 > buf.length) throw new Error('pkt-line truncated');
    const head = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('not a pkt-line');
    const len = parseInt(head, 16);
    if (len === 0) {
      out.push({ kind: 'flush' });
      offset += 4;
      continue;
    }
    if (len === 1) {
      out.push({ kind: 'delim' });
      offset += 4;
      continue;
    }
    if (len < 4 || offset + len > buf.length) throw new Error('pkt-line length out of range');
    out.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + len) });
    offset += len;
  }
  return out;
}

function encodePktLines(lines: Array<string | 'flush' | 'delim'>): Buffer {
  const parts: Buffer[] = [];
  for (const line of lines) {
    if (line === 'flush') parts.push(PKT_FLUSH);
    else if (line === 'delim') parts.push(PKT_DELIM);
    else parts.push(pktLine(line));
  }
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------
// git objects: packfile read/write, trees, commits
// ---------------------------------------------------------------------------

type ObjectType = 'commit' | 'tree' | 'blob' | 'tag';
interface GitObject {
  type: ObjectType;
  data: Buffer;
}

const PACK_TYPE_NUM: Record<ObjectType, number> = { commit: 1, tree: 2, blob: 3, tag: 4 };
const PACK_NUM_TYPE: Record<number, ObjectType> = { 1: 'commit', 2: 'tree', 3: 'blob', 4: 'tag' };

function writePackObjectHeader(typeNum: number, size: number): Buffer {
  const bytes: number[] = [];
  let first = (typeNum << 4) | (size & 0x0f);
  size >>= 4;
  if (size > 0) first |= 0x80;
  bytes.push(first);
  while (size > 0) {
    let b = size & 0x7f;
    size >>= 7;
    if (size > 0) b |= 0x80;
    bytes.push(b);
  }
  return Buffer.from(bytes);
}

function writePack(objects: readonly GitObject[]): Buffer {
  const parts: Buffer[] = [];
  const header = Buffer.allocUnsafe(12);
  header.write('PACK', 0, 4, 'ascii');
  header.writeUInt32BE(2, 4);
  header.writeUInt32BE(objects.length, 8);
  parts.push(header);
  for (const object of objects) {
    parts.push(writePackObjectHeader(PACK_TYPE_NUM[object.type], object.data.length));
    parts.push(deflateSync(object.data));
  }
  const body = Buffer.concat(parts);
  return Buffer.concat([body, createHash('sha1').update(body).digest()]);
}

function readPackVarint(buf: Buffer, offset: number): { value: number; next: number } {
  let value = 0;
  let shift = 0;
  let pos = offset;
  for (;;) {
    if (pos >= buf.length) throw new Error('pack varint truncated');
    const byte = buf[pos];
    pos += 1;
    value |= (byte & 0x7f) << shift;
    shift += 7;
    if ((byte & 0x80) === 0) break;
  }
  return { value, next: pos };
}

function applyDelta(base: Buffer, delta: Buffer): Buffer {
  let pos = 0;
  const sourceSize = readPackVarint(delta, pos);
  pos = sourceSize.next;
  if (sourceSize.value !== base.length) throw new Error('delta base size mismatch');
  const targetSize = readPackVarint(delta, pos);
  pos = targetSize.next;
  const out = Buffer.alloc(targetSize.value);
  let written = 0;
  while (pos < delta.length) {
    const op = delta[pos];
    pos += 1;
    if (op & 0x80) {
      let copyOffset = 0;
      let copySize = 0;
      for (let i = 0; i < 4; i += 1) {
        if (op & (1 << i)) {
          copyOffset |= delta[pos] << (8 * i);
          pos += 1;
        }
      }
      for (let i = 0; i < 3; i += 1) {
        if (op & (0x10 << i)) {
          copySize |= delta[pos] << (8 * i);
          pos += 1;
        }
      }
      if (copySize === 0) copySize = 0x10000;
      base.copy(out, written, copyOffset, copyOffset + copySize);
      written += copySize;
    } else if (op > 0) {
      delta.copy(out, written, pos, pos + op);
      pos += op;
      written += op;
    } else {
      throw new Error('delta opcode 0');
    }
  }
  if (written !== targetSize.value) throw new Error('delta size mismatch');
  return out;
}

/** Parse a packfile of plain objects (the suite's client writes no deltas). */
function readPack(buf: Buffer): Map<string, GitObject> {
  if (buf.length < 12 || buf.subarray(0, 4).toString('ascii') !== 'PACK') {
    throw new Error('not a packfile');
  }
  const count = buf.readUInt32BE(8);
  const objects = new Map<string, GitObject>();
  let offset = 12;
  for (let i = 0; i < count; i += 1) {
    if (offset >= buf.length) throw new Error('pack truncated');
    const first = buf[offset];
    offset += 1;
    const typeNum = (first >> 4) & 0x07;
    let size = first & 0x0f;
    let shift = 4;
    let cont = first & 0x80;
    while (cont) {
      if (offset >= buf.length) throw new Error('pack header truncated');
      const byte = buf[offset];
      offset += 1;
      size |= (byte & 0x7f) << shift;
      shift += 7;
      cont = byte & 0x80;
    }
    if (typeNum === 6 || typeNum === 7) throw new Error('pack delta not supported');
    const type = PACK_NUM_TYPE[typeNum] as ObjectType | undefined;
    if (!type) throw new Error(`unknown pack object type ${typeNum}`);
    const { data, consumed } = inflatePrefix(buf.subarray(offset), size);
    offset += consumed;
    const object: GitObject = { type, data };
    objects.set(gitObjectId(type, data), object);
  }
  return objects;
}

// Inflate a zlib stream that is a prefix of `buf`, returning the inflated bytes
// and how many input bytes the stream consumed. The stream is self-terminating,
// so a binary search over the input length finds the shortest prefix that
// inflates to exactly `expectedSize` bytes.
function inflatePrefix(buf: Buffer, expectedSize: number): { data: Buffer; consumed: number } {
  let lo = 1;
  let hi = buf.length;
  let found: { data: Buffer; consumed: number } | null = null;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    try {
      const data = inflateSync(buf.subarray(0, mid));
      if (data.length === expectedSize) {
        found = { data, consumed: mid };
        hi = mid - 1;
      } else if (data.length < expectedSize) {
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    } catch {
      lo = mid + 1;
    }
  }
  if (found) return found;
  // Fallback: inflate the whole remainder (valid when this is the last object).
  const data = inflateSync(buf);
  if (data.length !== expectedSize) throw new Error('pack object size mismatch');
  return { data, consumed: buf.length };
}

interface TreeEntry {
  mode: string;
  name: string;
  oid: string;
}

function parseTree(data: Buffer): TreeEntry[] {
  const entries: TreeEntry[] = [];
  let offset = 0;
  while (offset < data.length) {
    const space = data.indexOf(0x20, offset);
    const nul = data.indexOf(0x00, space + 1);
    if (space < 0 || nul < 0 || nul + 21 > data.length) throw new Error('bad tree entry');
    entries.push({
      mode: data.subarray(offset, space).toString('utf8'),
      name: data.subarray(space + 1, nul).toString('utf8'),
      oid: data.subarray(nul + 1, nul + 21).toString('hex'),
    });
    offset = nul + 21;
  }
  return entries;
}

interface CommitInfo {
  tree: string;
  parents: string[];
  author: string;
  committer: string;
  message: string;
}

function parseCommit(data: Buffer): CommitInfo {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let tree = '';
  const parents: string[] = [];
  let author = '';
  let committer = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('tree ')) tree = line.slice(5).trim();
    else if (line.startsWith('parent ')) parents.push(line.slice(7).trim());
    else if (line.startsWith('author ')) author = line.slice(7);
    else if (line.startsWith('committer ')) committer = line.slice(10);
  }
  return { tree, parents, author, committer, message };
}

function parseTag(data: Buffer): { object: string; type: string; tag: string; tagger: string; message: string } {
  const text = data.toString('utf8');
  const split = text.indexOf('\n\n');
  const head = split < 0 ? text : text.slice(0, split);
  const message = split < 0 ? '' : text.slice(split + 2);
  let object = '';
  let type = '';
  let tag = '';
  let tagger = '';
  for (const line of head.split('\n')) {
    if (line.startsWith('object ')) object = line.slice(7).trim();
    else if (line.startsWith('type ')) type = line.slice(5).trim();
    else if (line.startsWith('tag ')) tag = line.slice(4).trim();
    else if (line.startsWith('tagger ')) tagger = line.slice(7);
  }
  return { object, type, tag, tagger, message };
}

// ---------------------------------------------------------------------------
// the store
// ---------------------------------------------------------------------------

interface Label {
  name: string;
  color: string;
}

interface Issue {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  labels: Label[];
  seq: number;
}

interface IssueComment {
  id: number;
  body: string;
  user: string;
}

interface Pull {
  id: number;
  number: number;
  title: string;
  body: string;
  state: 'open' | 'closed';
  merged: boolean;
  mergedAt: string | null;
  mergeCommitSha: string | null;
  head: string;
  base: string;
  headSha: string;
  baseSha: string;
  seq: number;
}

interface Repo {
  id: number;
  owner: string;
  name: string;
  description: string;
  private: boolean;
  defaultBranch: string;
  objects: Map<string, GitObject>;
  refs: Map<string, string>;
  labels: Map<string, Label>;
  issues: Issue[];
  pulls: Pull[];
  comments: Map<number, IssueComment[]>;
  nextNumber: number;
  seq: number;
}

const repos = new Map<string, Repo>();
let repoIdCounter = 0;
let issueIdCounter = 0;
let commentIdCounter = 0;
let requestCounter = 0;

function repoKey(owner: string, name: string): string {
  return `${owner}/${name}`;
}

function getRepo(owner: string, name: string): Repo | undefined {
  return repos.get(repoKey(owner, name));
}

function createRepoRecord(owner: string, name: string, description: string, isPrivate: boolean): Repo {
  repoIdCounter += 1;
  const repo: Repo = {
    id: repoIdCounter,
    owner,
    name,
    description,
    private: isPrivate,
    defaultBranch: DEFAULT_BRANCH,
    objects: new Map(),
    refs: new Map(),
    labels: new Map(),
    issues: [],
    pulls: [],
    comments: new Map(),
    nextNumber: 1,
    seq: repoIdCounter,
  };
  repos.set(repoKey(owner, name), repo);
  return repo;
}

// ---------------------------------------------------------------------------
// git store operations on a repo
// ---------------------------------------------------------------------------

type FileMap = Map<string, string>; // path -> blob oid

function storeObject(repo: Repo, type: ObjectType, data: Buffer): string {
  const oid = gitObjectId(type, data);
  if (!repo.objects.has(oid)) repo.objects.set(oid, { type, data });
  return oid;
}

/** Build (and store) the tree objects for a flat file map; returns the root tree oid. */
function buildTrees(repo: Repo, files: FileMap): string {
  // Group paths into a nested structure, then write trees bottom-up.
  interface DirNode {
    files: Map<string, string>;
    dirs: Map<string, DirNode>;
  }
  const root: DirNode = { files: new Map(), dirs: new Map() };
  for (const [path, oid] of files) {
    const parts = path.split('/');
    let node = root;
    for (let i = 0; i < parts.length - 1; i += 1) {
      let child = node.dirs.get(parts[i]);
      if (!child) {
        child = { files: new Map(), dirs: new Map() };
        node.dirs.set(parts[i], child);
      }
      node = child;
    }
    node.files.set(parts[parts.length - 1], oid);
  }
  const writeDir = (node: DirNode): string => {
    const entries: Array<{ mode: string; name: string; oid: string; isDir: boolean }> = [];
    for (const [name, oid] of node.files) entries.push({ mode: '100644', name, oid, isDir: false });
    for (const [name, child] of node.dirs) entries.push({ mode: '40000', name, oid: writeDir(child), isDir: true });
    // Git tree order: by name, directories sorting as if the name ends with '/'.
    entries.sort((a, b) => {
      const an = a.isDir ? `${a.name}/` : a.name;
      const bn = b.isDir ? `${b.name}/` : b.name;
      return an < bn ? -1 : an > bn ? 1 : 0;
    });
    const parts: Buffer[] = [];
    for (const entry of entries) {
      parts.push(Buffer.from(`${entry.mode} ${entry.name}\0`, 'utf8'));
      parts.push(Buffer.from(entry.oid, 'hex'));
    }
    return storeObject(repo, 'tree', Buffer.concat(parts));
  };
  return writeDir(root);
}

/** The flat file map of a commit's tree (path -> blob oid), walked from the tree. */
function treeFiles(repo: Repo, treeOid: string): FileMap {
  const files: FileMap = new Map();
  const walk = (oid: string, prefix: string): void => {
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      const path = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.mode === '40000') walk(entry.oid, path);
      else files.set(path, entry.oid);
    }
  };
  walk(treeOid, '');
  return files;
}

function commitFiles(repo: Repo, commitOid: string): FileMap {
  const object = repo.objects.get(commitOid);
  if (!object || object.type !== 'commit') return new Map();
  return treeFiles(repo, parseCommit(object.data).tree);
}

/** Create a commit object (stored) on top of `parents` with `files` as its tree. */
function makeCommit(repo: Repo, parents: string[], files: FileMap, message: string): string {
  const treeOid = buildTrees(repo, files);
  const lines = [`tree ${treeOid}`];
  for (const parent of parents) lines.push(`parent ${parent}`);
  lines.push(`author ${FIXED_IDENT}`, `committer ${FIXED_IDENT}`, '', message);
  const data = Buffer.from(lines.join('\n'), 'utf8');
  return storeObject(repo, 'commit', data);
}

/** All commit oids reachable from `roots` (peeling tags), with their depth. */
function reachableCommits(repo: Repo, roots: readonly string[]): Map<string, number> {
  const depths = new Map<string, number>();
  const queue: Array<{ oid: string; depth: number }> = [];
  const peel = (oid: string): string | null => {
    let current = oid;
    for (let i = 0; i < 10; i += 1) {
      const object = repo.objects.get(current);
      if (!object) return null;
      if (object.type === 'commit') return current;
      if (object.type === 'tag') {
        current = parseTag(object.data).object;
        continue;
      }
      return null;
    }
    return null;
  };
  for (const root of roots) {
    const commit = peel(root);
    if (commit && !depths.has(commit)) {
      depths.set(commit, 0);
      queue.push({ oid: commit, depth: 0 });
    }
  }
  while (queue.length > 0) {
    const { oid, depth } = queue.shift()!;
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) {
      if (!depths.has(parent)) {
        depths.set(parent, depth + 1);
        queue.push({ oid: parent, depth: depth + 1 });
      }
    }
  }
  return depths;
}

/** Every object oid reachable from `commitOids` (commits, trees, blobs, tags). */
function reachableObjects(repo: Repo, commitOids: readonly string[]): Set<string> {
  const out = new Set<string>();
  const commits = reachableCommits(repo, commitOids);
  const walkTree = (treeOid: string): void => {
    if (out.has(treeOid)) return;
    out.add(treeOid);
    const object = repo.objects.get(treeOid);
    if (!object || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      if (entry.mode === '40000') walkTree(entry.oid);
      else out.add(entry.oid);
    }
  };
  for (const commitOid of commits.keys()) {
    out.add(commitOid);
    const object = repo.objects.get(commitOid);
    if (object && object.type === 'commit') walkTree(parseCommit(object.data).tree);
  }
  return out;
}

function isAncestor(repo: Repo, ancestor: string, descendant: string): boolean {
  if (ancestor === descendant) return true;
  return reachableCommits(repo, [descendant]).has(ancestor);
}

/** Commits reachable from a ref tip, newest first (insertion order is not kept, so sort by graph depth). */
function commitsFrom(repo: Repo, tip: string): string[] {
  const depths = reachableCommits(repo, [tip]);
  // BFS order from the tip is newest-first for linear histories; for merges,
  // sort by depth (shallowest first) and keep discovery order within a depth.
  const order: string[] = [];
  const seen = new Set<string>();
  const queue = [tip];
  seen.add(tip);
  while (queue.length > 0) {
    const oid = queue.shift()!;
    order.push(oid);
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) {
      if (!seen.has(parent) && depths.has(parent)) {
        seen.add(parent);
        queue.push(parent);
      }
    }
  }
  return order;
}

/** The first common ancestor of two commits (nearest to `a`), or null. */
function mergeBase(repo: Repo, a: string, b: string): string | null {
  const aAncestors = reachableCommits(repo, [a]);
  const queue = [b];
  const seen = new Set<string>([b]);
  while (queue.length > 0) {
    const oid = queue.shift()!;
    if (aAncestors.has(oid)) return oid;
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) {
      if (!seen.has(parent)) {
        seen.add(parent);
        queue.push(parent);
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// issues, pull requests, merges (shared by REST, GraphQL and MCP)
// ---------------------------------------------------------------------------

function issueObject(repo: Repo, issue: Issue): Record<string, unknown> {
  return {
    id: issue.id,
    number: issue.number,
    title: issue.title,
    body: issue.body,
    state: issue.state,
    labels: issue.labels.map((label) => ({ name: label.name, color: label.color })),
    user: { login: VIEWER_LOGIN, id: VIEWER_ID },
    html_url: `/repos/${repo.owner}/${repo.name}/issues/${issue.number}`,
  };
}

function pullObject(repo: Repo, pull: Pull): Record<string, unknown> {
  return {
    id: pull.id,
    number: pull.number,
    title: pull.title,
    body: pull.body,
    state: pull.state,
    merged: pull.merged,
    merged_at: pull.mergedAt,
    merge_commit_sha: pull.mergeCommitSha,
    head: { ref: pull.head, sha: pull.headSha, label: `${repo.owner}:${pull.head}` },
    base: { ref: pull.base, sha: pull.baseSha, label: `${repo.owner}:${pull.base}` },
    user: { login: VIEWER_LOGIN, id: VIEWER_ID },
    html_url: `/repos/${repo.owner}/${repo.name}/pull/${pull.number}`,
  };
}

function repoObject(repo: Repo): Record<string, unknown> {
  return {
    id: repo.id,
    name: repo.name,
    full_name: `${repo.owner}/${repo.name}`,
    owner: { login: repo.owner, id: VIEWER_ID },
    private: repo.private,
    description: repo.description,
    default_branch: repo.defaultBranch,
    has_issues: true,
    html_url: `/repos/${repo.owner}/${repo.name}`,
    url: `/api/v3/repos/${repo.owner}/${repo.name}`,
  };
}

function createIssueRecord(repo: Repo, title: string, body: string, labelNames: readonly string[]): Issue | { error: string } {
  const labels: Label[] = [];
  for (const name of labelNames) {
    const label = repo.labels.get(name);
    if (!label) return { error: `Label "${name}" does not exist` };
    labels.push(label);
  }
  issueIdCounter += 1;
  const issue: Issue = {
    id: issueIdCounter,
    number: repo.nextNumber,
    title,
    body,
    state: 'open',
    labels,
    seq: repo.nextNumber,
  };
  repo.nextNumber += 1;
  repo.issues.push(issue);
  return issue;
}

function createPullRecord(repo: Repo, title: string, body: string, head: string, base: string): Pull | { error: string } {
  const headOid = repo.refs.get(`refs/heads/${head}`);
  const baseOid = repo.refs.get(`refs/heads/${base}`);
  if (!headOid) return { error: `Head branch "${head}" does not exist` };
  if (!baseOid) return { error: `Base branch "${base}" does not exist` };
  const existing = repo.pulls.find((pull) => pull.head === head && pull.base === base && pull.state === 'open');
  if (existing) return { error: `A pull request from ${head} to ${base} is already open` };
  issueIdCounter += 1;
  const pull: Pull = {
    id: issueIdCounter,
    number: repo.nextNumber,
    title,
    body,
    state: 'open',
    merged: false,
    mergedAt: null,
    mergeCommitSha: null,
    head,
    base,
    headSha: headOid,
    baseSha: baseOid,
    seq: repo.nextNumber,
  };
  repo.nextNumber += 1;
  repo.pulls.push(pull);
  return pull;
}

/** Line counts for a changed file: additions/deletions by multiset line diff. */
function lineDiff(oldText: string, newText: string): { additions: number; deletions: number } {
  const oldLines = oldText === '' ? [] : oldText.split('\n');
  const newLines = newText === '' ? [] : newText.split('\n');
  const oldCount = new Map<string, number>();
  for (const line of oldLines) oldCount.set(line, (oldCount.get(line) ?? 0) + 1);
  let additions = 0;
  for (const line of newLines) {
    const remaining = oldCount.get(line) ?? 0;
    if (remaining > 0) oldCount.set(line, remaining - 1);
    else additions += 1;
  }
  let deletions = 0;
  for (const remaining of oldCount.values()) deletions += remaining;
  return { additions, deletions };
}

interface PullFile {
  filename: string;
  status: 'added' | 'removed' | 'modified';
  additions: number;
  deletions: number;
  changes: number;
}

/** The files changed between a pull request's base tip and head tip. */
function pullFiles(repo: Repo, pull: Pull): PullFile[] {
  const baseFiles = commitFiles(repo, pull.baseSha);
  const headFiles = commitFiles(repo, pull.headSha);
  const out: PullFile[] = [];
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys()]);
  for (const path of [...paths].sort()) {
    const baseOid = baseFiles.get(path);
    const headOid = headFiles.get(path);
    if (baseOid === headOid) continue;
    if (baseOid === undefined && headOid !== undefined) {
      const blob = repo.objects.get(headOid);
      const text = blob ? blob.data.toString('utf8') : '';
      const lines = text === '' ? 0 : text.split('\n').length;
      out.push({ filename: path, status: 'added', additions: lines, deletions: 0, changes: lines });
    } else if (headOid === undefined && baseOid !== undefined) {
      const blob = repo.objects.get(baseOid);
      const text = blob ? blob.data.toString('utf8') : '';
      const lines = text === '' ? 0 : text.split('\n').length;
      out.push({ filename: path, status: 'removed', additions: 0, deletions: lines, changes: lines });
    } else if (baseOid !== undefined && headOid !== undefined) {
      const oldText = repo.objects.get(baseOid)?.data.toString('utf8') ?? '';
      const newText = repo.objects.get(headOid)?.data.toString('utf8') ?? '';
      const { additions, deletions } = lineDiff(oldText, newText);
      out.push({ filename: path, status: 'modified', additions, deletions, changes: additions + deletions });
    }
  }
  return out;
}

/** Whether a pull request can merge cleanly (three-way, file by file). */
function pullMergeable(repo: Repo, pull: Pull): boolean {
  const headOid = repo.refs.get(`refs/heads/${pull.head}`);
  const baseOid = repo.refs.get(`refs/heads/${pull.base}`);
  if (!headOid || !baseOid) return false;
  const base = mergeBase(repo, headOid, baseOid);
  if (base === null) return false;
  const baseFiles = commitFiles(repo, base);
  const headFiles = commitFiles(repo, headOid);
  const tipFiles = commitFiles(repo, baseOid);
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys(), ...tipFiles.keys()]);
  for (const path of paths) {
    const b = baseFiles.get(path);
    const h = headFiles.get(path);
    const t = tipFiles.get(path);
    if (h === b) continue;
    if (t === b) continue;
    if (h === t) continue;
    return false;
  }
  return true;
}

/** Squash-merge a pull request onto its base branch. Returns the merge commit sha, or null on conflict. */
function mergePullRequest(repo: Repo, pull: Pull): string | null {
  if (pull.state !== 'open') return null;
  const headOid = repo.refs.get(`refs/heads/${pull.head}`);
  const baseOid = repo.refs.get(`refs/heads/${pull.base}`);
  if (!headOid || !baseOid) return null;
  const base = mergeBase(repo, headOid, baseOid);
  if (base === null) return null;
  const baseFiles = commitFiles(repo, base);
  const headFiles = commitFiles(repo, headOid);
  const tipFiles = commitFiles(repo, baseOid);
  const merged = new Map<string, string>(tipFiles);
  const paths = new Set([...baseFiles.keys(), ...headFiles.keys(), ...tipFiles.keys()]);
  for (const path of paths) {
    const b = baseFiles.get(path);
    const h = headFiles.get(path);
    const t = tipFiles.get(path);
    if (h === b) continue;
    if (t === b) {
      if (h === undefined) merged.delete(path);
      else merged.set(path, h);
      continue;
    }
    if (h === t) continue;
    return null; // both sides changed the path differently
  }
  const message = `Merge pull request #${pull.number} from ${repo.owner}/${pull.head}`;
  const sha = makeCommit(repo, [baseOid], merged, message);
  repo.refs.set(`refs/heads/${pull.base}`, sha);
  pull.state = 'closed';
  pull.merged = true;
  pull.mergedAt = FIXED_ISO;
  pull.mergeCommitSha = sha;
  pull.baseSha = sha;
  return sha;
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

function requestId(): string {
  requestCounter += 1;
  return `req-${requestCounter}`;
}

function sendJson(res: ServerResponse, status: number, body: unknown, extraHeaders: Record<string, string> = {}): void {
  const text = `${JSON.stringify(body)}\n`;
  res.writeHead(status, {
    'content-type': JSON_TYPE,
    'content-length': Buffer.byteLength(text),
    'x-github-request-id': requestId(),
    ...extraHeaders,
  });
  res.end(text);
}

function sendEmpty(res: ServerResponse, status: number, extraHeaders: Record<string, string> = {}): void {
  res.writeHead(status, { 'x-github-request-id': requestId(), ...extraHeaders });
  res.end();
}

function sendError(res: ServerResponse, status: number, message: string): void {
  sendJson(res, status, { message });
}

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > 32 * 1024 * 1024) {
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function parseJsonBody(raw: Buffer): unknown {
  if (raw.length === 0) return {};
  return JSON.parse(raw.toString('utf8'));
}

function isAuthed(req: IncomingMessage): boolean {
  const header = req.headers.authorization;
  return typeof header === 'string' && header === `Bearer ${TOKEN}`;
}

function urlOf(req: IncomingMessage): URL {
  return new URL(req.url ?? '/', 'http://entry');
}

function queryParams(url: URL): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of url.searchParams) out[key] = value;
  return out;
}

function pageOf(query: Record<string, string>): { page: number; perPage: number } {
  const page = Math.max(1, parseInt(query.page ?? '1', 10) || 1);
  const perPage = Math.min(100, Math.max(1, parseInt(query.per_page ?? '30', 10) || 30));
  return { page, perPage };
}

function paginate<T>(items: readonly T[], query: Record<string, string>): { page: T[]; totalPages: number; pageNum: number; perPage: number } {
  const { page, perPage } = pageOf(query);
  const totalPages = Math.max(1, Math.ceil(items.length / perPage));
  const start = (page - 1) * perPage;
  return { page: items.slice(start, start + perPage), totalPages, pageNum: page, perPage };
}

function linkHeader(req: IncomingMessage, url: URL, query: Record<string, string>, pageNum: number, totalPages: number): string | null {
  if (pageNum >= totalPages) return null;
  const host = req.headers.host ?? 'entry';
  const next = new URL(url.pathname, `http://${host}`);
  for (const [key, value] of url.searchParams) {
    if (key !== 'page') next.searchParams.set(key, value);
  }
  next.searchParams.set('page', String(pageNum + 1));
  return `<${next.toString()}>; rel="next"`;
}

// ---------------------------------------------------------------------------
// REST v3
// ---------------------------------------------------------------------------

function resolveRepo(req: IncomingMessage, owner: string, name: string): { repo: Repo } | { status: number; message: string } {
  if (!isAuthed(req)) return { status: 401, message: 'Requires authentication' };
  if (owner !== VIEWER_LOGIN) return { status: 404, message: 'Not Found' };
  const repo = getRepo(owner, name);
  if (!repo) return { status: 404, message: 'Not Found' };
  return { repo };
}

function handleRest(req: IncomingMessage, res: ServerResponse, path: string, url: URL, rawBody: Buffer): boolean {
  const method = req.method ?? 'GET';
  const query = queryParams(url);
  const segments = path.split('/').filter((s) => s !== '');

  // API root and meta are public (no token needed); everything else under /api/v3 needs one.
  if (method === 'GET' && (path === '/api/v3' || path === '/api/v3/')) {
    sendJson(res, 200, { current_user_url: '/api/v3/user', rate_limit_url: '/api/v3/rate_limit' }, { 'x-oauth-scopes': 'repo, read:org' });
    return true;
  }
  if (method === 'GET' && path === '/api/v3/meta') {
    sendJson(res, 200, { installed_version: SERVER_VERSION });
    return true;
  }
  if (!path.startsWith('/api/v3/')) return false;

  let body: unknown = {};
  if (rawBody.length > 0 && (method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE')) {
    try {
      body = parseJsonBody(rawBody);
    } catch {
      sendError(res, 400, 'Problems parsing JSON');
      return true;
    }
  }
  const bodyObj = (typeof body === 'object' && body !== null && !Array.isArray(body) ? body : {}) as Record<string, unknown>;

  // GET /api/v3/user — the token owner's login.
  if (method === 'GET' && path === '/api/v3/user') {
    if (!isAuthed(req)) {
      sendError(res, 401, 'Requires authentication');
      return true;
    }
    sendJson(res, 200, { login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL, type: 'User' });
    return true;
  }

  // POST /api/v3/user/repos — create a repository.
  if (method === 'POST' && path === '/api/v3/user/repos') {
    if (!isAuthed(req)) {
      sendError(res, 401, 'Requires authentication');
      return true;
    }
    const name = bodyObj.name;
    if (typeof name !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(name)) {
      sendError(res, 422, 'Invalid repository name');
      return true;
    }
    if (getRepo(VIEWER_LOGIN, name)) {
      sendError(res, 422, 'Repository already exists');
      return true;
    }
    const repo = createRepoRecord(
      VIEWER_LOGIN,
      name,
      typeof bodyObj.description === 'string' ? bodyObj.description : '',
      bodyObj.private === true,
    );
    sendJson(res, 201, repoObject(repo));
    return true;
  }

  // GET /api/v3/user/repos — the viewer's repositories, paginated with Link rel="next".
  if (method === 'GET' && path === '/api/v3/user/repos') {
    if (!isAuthed(req)) {
      sendError(res, 401, 'Requires authentication');
      return true;
    }
    const all = [...repos.values()].filter((r) => r.owner === VIEWER_LOGIN).sort((a, b) => a.seq - b.seq);
    const { page, totalPages, pageNum } = paginate(all, query);
    const link = linkHeader(req, url, query, pageNum, totalPages);
    sendJson(res, 200, page.map((r) => repoObject(r)), link ? { link } : {});
    return true;
  }

  // /api/v3/repos/{owner}/{repo}[...]
  if (segments.length >= 4 && segments[0] === 'api' && segments[1] === 'v3' && segments[2] === 'repos') {
    const owner = decodeURIComponent(segments[3]);
    const repoName = decodeURIComponent(segments[4]);
    const rest = segments.slice(5);
    const resolved = resolveRepo(req, owner, repoName);
    if ('status' in resolved) {
      sendError(res, resolved.status, resolved.message);
      return true;
    }
    const repo = resolved.repo;

    // GET /repos/{o}/{r}
    if (rest.length === 0) {
      if (method === 'GET') {
        sendJson(res, 200, repoObject(repo));
        return true;
      }
      if (method === 'PATCH') {
        if (typeof bodyObj.description === 'string') repo.description = bodyObj.description;
        sendJson(res, 200, repoObject(repo));
        return true;
      }
      if (method === 'DELETE') {
        repos.delete(repoKey(owner, repoName));
        sendEmpty(res, 204);
        return true;
      }
      sendError(res, 404, 'Not Found');
      return true;
    }

    const sub = rest[0];

    // GET /repos/{o}/{r}/branches and /branches/{branch}
    if (sub === 'branches') {
      if (method === 'GET' && rest.length === 1) {
        const list = [...repo.refs.keys()]
          .filter((ref) => ref.startsWith('refs/heads/'))
          .sort()
          .map((ref) => ({ name: ref.slice('refs/heads/'.length), commit: { sha: repo.refs.get(ref) } }));
        sendJson(res, 200, list);
        return true;
      }
      if (method === 'GET' && rest.length === 2) {
        const branch = decodeURIComponent(rest[1]);
        const sha = repo.refs.get(`refs/heads/${branch}`);
        if (!sha) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, { name: branch, commit: { sha } });
        return true;
      }
    }

    // POST /repos/{o}/{r}/git/refs and GET /git/refs/heads/{branch}
    if (sub === 'git' && rest[1] === 'refs') {
      if (method === 'POST' && rest.length === 2) {
        const ref = bodyObj.ref;
        const sha = bodyObj.sha;
        if (typeof ref !== 'string' || !ref.startsWith('refs/') || typeof sha !== 'string' || !isOid(sha)) {
          sendError(res, 422, 'Invalid ref or sha');
          return true;
        }
        if (!repo.objects.has(sha)) {
          sendError(res, 422, 'Object does not exist');
          return true;
        }
        if (repo.refs.has(ref)) {
          sendError(res, 422, 'Reference already exists');
          return true;
        }
        repo.refs.set(ref, sha);
        sendJson(res, 201, { ref, object: { sha } });
        return true;
      }
      if (method === 'GET' && rest.length === 4 && rest[2] === 'heads') {
        const branch = decodeURIComponent(rest[3]);
        const sha = repo.refs.get(`refs/heads/${branch}`);
        if (!sha) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, { ref: `refs/heads/${branch}`, object: { sha }, sha });
        return true;
      }
    }

    // GET /repos/{o}/{r}/commits
    if (sub === 'commits' && method === 'GET' && rest.length === 1) {
      const refName = query.sha ?? repo.defaultBranch;
      let tip = repo.refs.get(`refs/heads/${refName}`);
      if (!tip && isOid(refName)) tip = refName;
      if (!tip || !repo.objects.has(tip)) {
        sendJson(res, 200, []);
        return true;
      }
      const commits = commitsFrom(repo, tip).map((oid) => {
        const info = parseCommit(repo.objects.get(oid)!.data);
        const authorBits = info.author.match(/^(.*?) <(.*?)> /);
        const committerBits = info.committer.match(/^(.*?) <(.*?)> /);
        return {
          sha: oid,
          commit: {
            message: info.message,
            author: { name: authorBits?.[1] ?? '', email: authorBits?.[2] ?? '' },
            committer: { name: committerBits?.[1] ?? '', email: committerBits?.[2] ?? '' },
          },
          parents: info.parents.map((p) => ({ sha: p })),
        };
      });
      const { page } = paginate(commits, query);
      sendJson(res, 200, page);
      return true;
    }

    // /repos/{o}/{r}/contents/{path...}
    if (sub === 'contents') {
      const contentPath = rest.slice(1).map((s) => decodeURIComponent(s)).join('/');
      return handleContents(req, res, repo, contentPath, query, bodyObj, method);
    }

    // /repos/{o}/{r}/labels
    if (sub === 'labels') {
      if (method === 'POST' && rest.length === 1) {
        const name = bodyObj.name;
        if (typeof name !== 'string' || name === '') {
          sendError(res, 422, 'Invalid label name');
          return true;
        }
        const label: Label = { name, color: typeof bodyObj.color === 'string' ? bodyObj.color : 'ededed' };
        repo.labels.set(name, label);
        sendJson(res, 201, label);
        return true;
      }
      if (method === 'GET' && rest.length === 1) {
        sendJson(res, 200, [...repo.labels.values()]);
        return true;
      }
    }

    // /repos/{o}/{r}/issues[/{n}[/comments]]
    if (sub === 'issues') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const title = bodyObj.title;
          if (typeof title !== 'string' || title === '') {
            sendError(res, 422, 'Invalid issue title');
            return true;
          }
          const labels = Array.isArray(bodyObj.labels) ? bodyObj.labels.filter((l): l is string => typeof l === 'string') : [];
          const created = createIssueRecord(repo, title, typeof bodyObj.body === 'string' ? bodyObj.body : '', labels);
          if ('error' in created) {
            sendError(res, 422, created.error);
            return true;
          }
          sendJson(res, 201, issueObject(repo, created));
          return true;
        }
        if (method === 'GET') {
          const state = query.state ?? 'open';
          let list = [...repo.issues];
          if (state !== 'all') list = list.filter((i) => i.state === state);
          const direction = query.direction ?? 'desc';
          list.sort((a, b) => (direction === 'asc' ? a.seq - b.seq : b.seq - a.seq));
          const { page, totalPages, pageNum } = paginate(list, query);
          const link = linkHeader(req, url, query, pageNum, totalPages);
          sendJson(res, 200, page.map((i) => issueObject(repo, i)), link ? { link } : {});
          return true;
        }
      }
      const issueNumber = parseInt(rest[1] ?? '', 10);
      const issue = repo.issues.find((i) => i.number === issueNumber);
      if (rest.length === 2) {
        if (!issue) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        if (method === 'GET') {
          sendJson(res, 200, issueObject(repo, issue));
          return true;
        }
        if (method === 'PATCH') {
          if (bodyObj.state === 'open' || bodyObj.state === 'closed') issue.state = bodyObj.state;
          if (typeof bodyObj.title === 'string') issue.title = bodyObj.title;
          if (typeof bodyObj.body === 'string') issue.body = bodyObj.body;
          sendJson(res, 200, issueObject(repo, issue));
          return true;
        }
      }
      if (rest.length === 3 && rest[2] === 'comments') {
        if (!issue) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        if (method === 'POST') {
          if (typeof bodyObj.body !== 'string' || bodyObj.body === '') {
            sendError(res, 422, 'Invalid comment body');
            return true;
          }
          commentIdCounter += 1;
          const comment: IssueComment = { id: commentIdCounter, body: bodyObj.body, user: VIEWER_LOGIN };
          const list = repo.comments.get(issue.number) ?? [];
          list.push(comment);
          repo.comments.set(issue.number, list);
          sendJson(res, 201, { id: comment.id, body: comment.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID } });
          return true;
        }
        if (method === 'GET') {
          const list = repo.comments.get(issue.number) ?? [];
          sendJson(res, 200, list.map((c) => ({ id: c.id, body: c.body, user: { login: VIEWER_LOGIN, id: VIEWER_ID } })));
          return true;
        }
      }
    }

    // /repos/{o}/{r}/pulls[/{n}[/files|/merge]]
    if (sub === 'pulls') {
      if (rest.length === 1) {
        if (method === 'POST') {
          const title = bodyObj.title;
          const head = bodyObj.head;
          const base = bodyObj.base;
          if (typeof title !== 'string' || typeof head !== 'string' || typeof base !== 'string') {
            sendError(res, 422, 'Invalid pull request');
            return true;
          }
          const created = createPullRecord(repo, title, typeof bodyObj.body === 'string' ? bodyObj.body : '', head, base);
          if ('error' in created) {
            sendError(res, 422, created.error);
            return true;
          }
          sendJson(res, 201, pullObject(repo, created));
          return true;
        }
        if (method === 'GET') {
          const state = query.state ?? 'open';
          let list = [...repo.pulls];
          if (state !== 'all') list = list.filter((p) => p.state === state);
          list.sort((a, b) => b.seq - a.seq);
          const { page, totalPages, pageNum } = paginate(list, query);
          const link = linkHeader(req, url, query, pageNum, totalPages);
          sendJson(res, 200, page.map((p) => pullObject(repo, p)), link ? { link } : {});
          return true;
        }
      }
      const pullNumber = parseInt(rest[1] ?? '', 10);
      const pull = repo.pulls.find((p) => p.number === pullNumber);
      if (rest.length === 2) {
        if (!pull || method !== 'GET') {
          sendError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, pullObject(repo, pull));
        return true;
      }
      if (rest.length === 3 && rest[2] === 'files' && method === 'GET') {
        if (!pull) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        sendJson(res, 200, pullFiles(repo, pull));
        return true;
      }
      if (rest.length === 3 && rest[2] === 'merge' && method === 'PUT') {
        if (!pull) {
          sendError(res, 404, 'Not Found');
          return true;
        }
        if (pull.state !== 'open') {
          sendError(res, 405, 'Pull request is already closed');
          return true;
        }
        const sha = mergePullRequest(repo, pull);
        if (sha === null) {
          sendError(res, 405, 'Merge conflict');
          return true;
        }
        sendJson(res, 200, { sha, merged: true, message: 'Pull request successfully merged' });
        return true;
      }
    }
  }

  return false;
}

/** The tree oid at `dirPath` inside a root tree, or null. */
function treeOidAtPath(repo: Repo, rootTreeOid: string, dirPath: string): string | null {
  if (dirPath === '') return rootTreeOid;
  let current = rootTreeOid;
  for (const segment of dirPath.split('/')) {
    const object = repo.objects.get(current);
    if (!object || object.type !== 'tree') return null;
    const entry = parseTree(object.data).find((e) => e.name === segment && e.mode === '40000');
    if (!entry) return null;
    current = entry.oid;
  }
  return current;
}

/** The contents API: GET/PUT/DELETE one file or GET a directory listing. */
function handleContents(
  req: IncomingMessage,
  res: ServerResponse,
  repo: Repo,
  contentPath: string,
  query: Record<string, string>,
  bodyObj: Record<string, unknown>,
  method: string,
): boolean {
  const branchName = typeof bodyObj.branch === 'string' ? bodyObj.branch : query.ref ?? repo.defaultBranch;
  const refName = `refs/heads/${branchName}`;
  const tip = repo.refs.get(refName);

  if (method === 'GET') {
    if (!tip) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const files = commitFiles(repo, tip);
    const exact = files.get(contentPath);
    if (exact !== undefined) {
      const blob = repo.objects.get(exact)!;
      sendJson(res, 200, {
        type: 'file',
        encoding: 'base64',
        content: blob.data.toString('base64'),
        sha: exact,
        size: blob.data.length,
        name: contentPath.split('/').pop() ?? contentPath,
        path: contentPath,
      });
      return true;
    }
    // Directory listing: immediate children of contentPath ('' is the root).
    const prefix = contentPath === '' ? '' : `${contentPath}/`;
    const children = new Map<string, { type: 'file' | 'dir'; sha: string }>();
    for (const [path, oid] of files) {
      if (!path.startsWith(prefix)) continue;
      const rest = path.slice(prefix.length);
      if (rest === '') continue;
      const slash = rest.indexOf('/');
      if (slash === -1) {
        children.set(rest, { type: 'file', sha: oid });
      } else {
        const dirName = rest.slice(0, slash);
        if (!children.has(dirName)) {
          const rootTree = parseCommit(repo.objects.get(tip)!.data).tree;
          const treeOid = treeOidAtPath(repo, rootTree, `${prefix}${dirName}`);
          children.set(dirName, { type: 'dir', sha: treeOid ?? ZERO_OID });
        }
      }
    }
    if (children.size === 0) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const entries = [...children.entries()]
      .sort((a, b) => (a[0] < b[0] ? -1 : 1))
      .map(([name, entry]) => ({
        type: entry.type,
        name,
        path: prefix + name,
        sha: entry.sha,
        size: entry.type === 'file' ? (repo.objects.get(entry.sha)?.data.length ?? 0) : 0,
      }));
    sendJson(res, 200, entries);
    return true;
  }

  if (method === 'PUT') {
    const content = bodyObj.content;
    const message = bodyObj.message;
    if (typeof content !== 'string' || typeof message !== 'string') {
      sendError(res, 422, 'Invalid content');
      return true;
    }
    const bytes = b64decode(content);
    const currentFiles = tip ? commitFiles(repo, tip) : new Map<string, string>();
    const currentSha = currentFiles.get(contentPath);
    const givenSha = typeof bodyObj.sha === 'string' ? bodyObj.sha : undefined;
    if (givenSha !== undefined && currentSha !== givenSha) {
      sendError(res, 409, 'Conflict: sha does not match the current file');
      return true;
    }
    const blobOid = storeObject(repo, 'blob', bytes);
    const nextFiles = new Map(currentFiles);
    nextFiles.set(contentPath, blobOid);
    const parents = tip ? [tip] : [];
    const commitSha = makeCommit(repo, parents, nextFiles, message);
    repo.refs.set(refName, commitSha);
    const status = currentSha === undefined ? 201 : 200;
    sendJson(res, status, {
      content: {
        name: contentPath.split('/').pop() ?? contentPath,
        path: contentPath,
        sha: blobOid,
        size: bytes.length,
        type: 'file',
        encoding: 'base64',
        content: bytes.toString('base64'),
      },
      commit: { sha: commitSha },
    });
    return true;
  }

  if (method === 'DELETE') {
    if (!tip) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const currentFiles = commitFiles(repo, tip);
    const currentSha = currentFiles.get(contentPath);
    if (currentSha === undefined) {
      sendError(res, 404, 'Not Found');
      return true;
    }
    const givenSha = typeof bodyObj.sha === 'string' ? bodyObj.sha : undefined;
    if (givenSha !== undefined && givenSha !== currentSha) {
      sendError(res, 409, 'Conflict: sha does not match the current file');
      return true;
    }
    const message = typeof bodyObj.message === 'string' ? bodyObj.message : `Delete ${contentPath}`;
    const nextFiles = new Map(currentFiles);
    nextFiles.delete(contentPath);
    const commitSha = makeCommit(repo, [tip], nextFiles, message);
    repo.refs.set(refName, commitSha);
    sendJson(res, 200, { commit: { sha: commitSha } });
    return true;
  }

  sendError(res, 404, 'Not Found');
  return true;
}

// ---------------------------------------------------------------------------
// git smart HTTP
// ---------------------------------------------------------------------------

function gitCapabilitiesV0(service: 'upload' | 'receive'): string {
  const common = ['side-band-64k', 'thin-pack', 'ofs-delta', 'agent=github-core-clone/1.0.0', 'object-format=sha1', 'symref=HEAD:refs/heads/main'];
  if (service === 'upload') return [...common, 'multi_ack_detailed', 'shallow'].join(' ');
  return ['report-status', 'delete-refs', ...common].join(' ');
}

function sortedRefs(repo: Repo): Array<{ name: string; oid: string }> {
  return [...repo.refs.entries()]
    .map(([name, oid]) => ({ name, oid }))
    .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

function peeledOid(repo: Repo, refOid: string): string | null {
  const object = repo.objects.get(refOid);
  if (!object || object.type !== 'tag') return null;
  const tag = parseTag(object.data);
  const target = repo.objects.get(tag.object);
  if (!target || target.type !== 'commit') return null;
  return tag.object;
}

function v0Advertisement(repo: Repo, service: 'upload' | 'receive'): Buffer {
  const caps = gitCapabilitiesV0(service);
  const refs = sortedRefs(repo);
  const lines: Buffer[] = [];
  const serviceName = service === 'upload' ? 'git-upload-pack' : 'git-receive-pack';
  lines.push(pktLine(`# service=${serviceName}\n`), PKT_FLUSH);
  if (refs.length === 0) {
    lines.push(pktLine(`${ZERO_OID} capabilities^{}\0${caps}\n`));
  } else {
    const head = repo.refs.get('refs/heads/main');
    const headOid = head ?? refs[0].oid;
    lines.push(pktLine(`${headOid} HEAD\0${caps}\n`));
    for (const ref of refs) {
      lines.push(pktLine(`${ref.oid} ${ref.name}\n`));
      const peeled = peeledOid(repo, ref.oid);
      if (peeled) lines.push(pktLine(`${peeled} ${ref.name}^{}\n`));
    }
  }
  lines.push(PKT_FLUSH);
  return Buffer.concat(lines);
}

function v2Advertisement(): Buffer {
  return encodePktLines([
    'version 2\n',
    'ls-refs=unborn\n',
    'fetch=shallow\n',
    'object-format=sha1\n',
    'agent=github-core-clone/1.0.0\n',
    'flush',
  ]);
}

/** The objects a fetch sends, plus the shallow-info boundary it reports. */
function computeFetch(
  repo: Repo,
  wants: readonly string[],
  haves: readonly string[],
  shallowList: readonly string[],
  depth: number | null,
): { objects: GitObject[]; shallow: string[]; unshallow: string[] } {
  const shallowSet = new Set(shallowList);
  // Included commits, depth-limited from the wants.
  const included = new Map<string, number>();
  const queue: Array<{ oid: string; depth: number }> = [];
  const peelToCommit = (oid: string): string | null => {
    const object = repo.objects.get(oid);
    if (!object) return null;
    if (object.type === 'commit') return oid;
    if (object.type === 'tag') return peelToCommit(parseTag(object.data).object);
    return null;
  };
  for (const want of wants) {
    const commit = peelToCommit(want);
    if (commit && !included.has(commit)) {
      included.set(commit, 0);
      queue.push({ oid: commit, depth: 0 });
    }
  }
  while (queue.length > 0) {
    const { oid, depth: d } = queue.shift()!;
    if (depth !== null && d + 1 >= depth) continue;
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    for (const parent of parseCommit(object.data).parents) {
      if (!included.has(parent) && repo.objects.has(parent)) {
        included.set(parent, d + 1);
        queue.push({ oid: parent, depth: d + 1 });
      }
    }
  }
  // Objects the client already holds: the closure of each have, without
  // descending past a shallow boundary commit's parents (a shallow clone
  // holds the boundary commit and its tree, not the history behind it).
  const held = new Set<string>();
  const heldCommits = new Set<string>();
  const heldQueue: string[] = [];
  for (const have of haves) {
    const commit = peelToCommit(have);
    if (commit && !heldCommits.has(commit)) {
      heldCommits.add(commit);
      heldQueue.push(commit);
    }
  }
  const walkTreeHeld = (treeOid: string): void => {
    if (held.has(treeOid)) return;
    held.add(treeOid);
    const object = repo.objects.get(treeOid);
    if (!object || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      if (entry.mode === '40000') walkTreeHeld(entry.oid);
      else held.add(entry.oid);
    }
  };
  while (heldQueue.length > 0) {
    const oid = heldQueue.shift()!;
    const object = repo.objects.get(oid);
    if (!object || object.type !== 'commit') continue;
    held.add(oid);
    walkTreeHeld(parseCommit(object.data).tree);
    if (shallowSet.has(oid)) continue; // the client does not hold this commit's parents
    for (const parent of parseCommit(object.data).parents) {
      if (!heldCommits.has(parent) && repo.objects.has(parent)) {
        heldCommits.add(parent);
        heldQueue.push(parent);
      }
    }
  }
  // The tag objects named by the wants travel too.
  const includedOids = new Set<string>();
  for (const want of wants) {
    if (repo.objects.has(want)) includedOids.add(want);
  }
  // Tree closure of the included commits only: a depth-limited fetch must
  // not carry the parents' trees, let alone the parents themselves.
  const walkTree = (treeOid: string): void => {
    if (includedOids.has(treeOid)) return;
    includedOids.add(treeOid);
    const object = repo.objects.get(treeOid);
    if (!object || object.type !== 'tree') return;
    for (const entry of parseTree(object.data)) {
      if (entry.mode === '40000') walkTree(entry.oid);
      else includedOids.add(entry.oid);
    }
  };
  for (const oid of included.keys()) {
    includedOids.add(oid);
    const object = repo.objects.get(oid);
    if (object && object.type === 'commit') walkTree(parseCommit(object.data).tree);
  }
  const sendOids = [...includedOids].filter((oid) => !held.has(oid)).sort();
  const objects: GitObject[] = [];
  for (const oid of sendOids) {
    const object = repo.objects.get(oid);
    if (object) objects.push(object);
  }
  const shallow: string[] = [];
  const unshallow: string[] = [];
  if (depth !== null) {
    for (const [oid] of included) {
      const object = repo.objects.get(oid);
      if (!object || object.type !== 'commit') continue;
      const parents = parseCommit(object.data).parents;
      const cut = parents.filter((p) => repo.objects.has(p) && !included.has(p));
      if (parents.length > 0 && cut.length > 0) shallow.push(oid);
      if (shallowSet.has(oid) && parents.every((p) => !repo.objects.has(p) || included.has(p))) unshallow.push(oid);
    }
    shallow.sort();
    unshallow.sort();
  }
  return { objects, shallow, unshallow };
}

function sidebandPackets(pack: Buffer): Buffer[] {
  const out: Buffer[] = [];
  const CHUNK = 32768;
  for (let offset = 0; offset < pack.length; offset += CHUNK) {
    const slice = pack.subarray(offset, Math.min(pack.length, offset + CHUNK));
    out.push(pktLine(Buffer.concat([Buffer.from([1]), slice])));
  }
  if (pack.length === 0) out.push(pktLine(Buffer.from([1])));
  return out;
}

/** Read pkt-lines from the start of `buf` until the first flush; return them and the offset where the pack bytes begin. */
function readPacketsUntilFlush(buf: Buffer): { packets: Pkt[]; packStart: number } {
  const packets: Pkt[] = [];
  let offset = 0;
  while (offset + 4 <= buf.length) {
    const head = buf.subarray(offset, offset + 4).toString('ascii');
    if (!/^[0-9a-fA-F]{4}$/.test(head)) throw new Error('not a pkt-line');
    const len = parseInt(head, 16);
    if (len === 0) {
      packets.push({ kind: 'flush' });
      offset += 4;
      break;
    }
    if (len === 1) {
      packets.push({ kind: 'delim' });
      offset += 4;
      continue;
    }
    if (len < 4 || offset + len > buf.length) throw new Error('pkt-line length out of range');
    packets.push({ kind: 'data', payload: buf.subarray(offset + 4, offset + len) });
    offset += len;
  }
  return { packets, packStart: offset };
}

function handleGit(req: IncomingMessage, res: ServerResponse, path: string, url: URL, rawBody: Buffer): boolean {
  const method = req.method ?? 'GET';
  const segments = path.split('/').filter((s) => s !== '');
  if (segments.length < 2 || !segments[1].endsWith('.git')) return false;
  const owner = decodeURIComponent(segments[0]);
  const repoName = decodeURIComponent(segments[1].slice(0, -'.git'.length));
  const tail = segments.slice(2).join('/');

  if (!isAuthed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return true;
  }
  if (owner !== VIEWER_LOGIN) {
    sendJson(res, 404, { message: 'Not Found' });
    return true;
  }
  const repo = getRepo(owner, repoName);
  if (!repo) {
    sendJson(res, 404, { message: 'Not Found' });
    return true;
  }

  // GET /{owner}/{repo}.git/info/refs?service=...
  if (method === 'GET' && tail === 'info/refs') {
    const service = url.searchParams.get('service');
    if (service === 'git-upload-pack') {
      const wantV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
      const body = wantV2 ? v2Advertisement() : v0Advertisement(repo, 'upload');
      res.writeHead(200, {
        'content-type': 'application/x-git-upload-pack-advertisement',
        'content-length': body.length,
        'x-github-request-id': requestId(),
      });
      res.end(body);
      return true;
    }
    if (service === 'git-receive-pack') {
      const body = v0Advertisement(repo, 'receive');
      res.writeHead(200, {
        'content-type': 'application/x-git-receive-pack-advertisement',
        'content-length': body.length,
        'x-github-request-id': requestId(),
      });
      res.end(body);
      return true;
    }
    sendJson(res, 400, { message: 'Unknown service' });
    return true;
  }

  // POST /{owner}/{repo}.git/git-upload-pack
  if (method === 'POST' && tail === 'git-upload-pack') {
    let packets: Pkt[];
    try {
      packets = decodePktLines(rawBody);
    } catch {
      sendJson(res, 400, { message: 'Not a pkt-line stream' });
      return true;
    }
    const wantV2 = (req.headers['git-protocol'] ?? '') === 'version=2';
    const lines = packets.filter((p): p is { kind: 'data'; payload: Buffer } => p.kind === 'data').map((p) => p.payload.toString('utf8'));
    try {
      if (wantV2) {
        const command = lines[0]?.replace(/\n$/, '') ?? '';
        if (command === 'command=ls-refs') {
          const prefixes: string[] = [];
          let peel = false;
          let symrefs = false;
          let unborn = false;
          for (const line of lines.slice(1)) {
            const text = line.replace(/\n$/, '');
            if (text === 'peel') peel = true;
            else if (text === 'symrefs') symrefs = true;
            else if (text === 'unborn') unborn = true;
            else if (text.startsWith('ref-prefix ')) prefixes.push(text.slice('ref-prefix '.length));
          }
          const keep = (name: string): boolean => prefixes.length === 0 || prefixes.some((p) => name.startsWith(p));
          const out: string[] = [];
          const headOid = repo.refs.get('refs/heads/main');
          if (prefixes.length === 0) {
            if (headOid) {
              out.push(`${headOid} HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
            } else if (unborn) {
              out.push(`unborn HEAD${symrefs ? ' symref-target:refs/heads/main' : ''}\n`);
            }
          }
          for (const ref of sortedRefs(repo)) {
            if (!keep(ref.name)) continue;
            let line = `${ref.oid} ${ref.name}`;
            if (peel) {
              const peeled = peeledOid(repo, ref.oid);
              if (peeled) line += ` peeled:${peeled}`;
            }
            out.push(`${line}\n`);
          }
          const body = Buffer.concat([encodePktLines(out), PKT_FLUSH]);
          res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'content-length': body.length, 'x-github-request-id': requestId() });
          res.end(body);
          return true;
        }
        if (command === 'command=fetch') {
          const wants: string[] = [];
          const haves: string[] = [];
          const shallowList: string[] = [];
          let depth: number | null = null;
          for (const line of lines.slice(1)) {
            const text = line.replace(/\n$/, '');
            if (text.startsWith('want ')) wants.push(text.slice(5).trim());
            else if (text.startsWith('have ')) haves.push(text.slice(5).trim());
            else if (text.startsWith('shallow ')) shallowList.push(text.slice(8).trim());
            else if (text.startsWith('deepen ')) depth = parseInt(text.slice(7).trim(), 10);
          }
          const { objects, shallow, unshallow } = computeFetch(repo, wants, haves, shallowList, depth);
          const pack = writePack(objects);
          const parts: Buffer[] = [];
          parts.push(pktLine('acknowledgments\n'), pktLine('NAK\n'), PKT_FLUSH);
          if (shallow.length > 0 || unshallow.length > 0) {
            parts.push(pktLine('shallow-info\n'));
            for (const oid of shallow) parts.push(pktLine(`shallow ${oid}\n`));
            for (const oid of unshallow) parts.push(pktLine(`unshallow ${oid}\n`));
            parts.push(PKT_FLUSH);
          }
          parts.push(pktLine('packfile\n'));
          parts.push(...sidebandPackets(pack));
          parts.push(PKT_FLUSH);
          const body = Buffer.concat(parts);
          res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'content-length': body.length, 'x-github-request-id': requestId() });
          res.end(body);
          return true;
        }
        sendJson(res, 400, { message: 'Unknown v2 command' });
        return true;
      }
      // v0 fetch
      const wants: string[] = [];
      const haves: string[] = [];
      const shallowList: string[] = [];
      let depth: number | null = null;
      let seenFlush = false;
      for (const packet of packets) {
        if (packet.kind === 'flush') {
          seenFlush = true;
          continue;
        }
        if (packet.kind !== 'data') continue;
        const text = packet.payload.toString('utf8').replace(/\n$/, '');
        if (!seenFlush) {
          if (text.startsWith('want ')) wants.push(text.split(' ')[1]);
          else if (text.startsWith('shallow ')) shallowList.push(text.slice(8).trim());
          else if (text.startsWith('deepen ')) depth = parseInt(text.slice(7).trim(), 10);
        } else {
          if (text.startsWith('have ')) haves.push(text.slice(5).trim());
        }
      }
      const { objects } = computeFetch(repo, wants, haves, shallowList, depth);
      const pack = writePack(objects);
      const parts: Buffer[] = [pktLine('NAK\n'), ...sidebandPackets(pack), PKT_FLUSH];
      const body = Buffer.concat(parts);
      res.writeHead(200, { 'content-type': 'application/x-git-upload-pack-result', 'content-length': body.length, 'x-github-request-id': requestId() });
      res.end(body);
      return true;
    } catch (err) {
      sendJson(res, 400, { message: err instanceof Error ? err.message : 'Bad request' });
      return true;
    }
  }

  // POST /{owner}/{repo}.git/git-receive-pack
  if (method === 'POST' && tail === 'git-receive-pack') {
    let packets: Pkt[];
    let packStart = 0;
    try {
      const read = readPacketsUntilFlush(rawBody);
      packets = read.packets;
      packStart = read.packStart;
    } catch {
      sendJson(res, 400, { message: 'Not a pkt-line stream' });
      return true;
    }
    // Command pkt-lines up to the first flush, then the pack bytes.
    const commands: Array<{ oldOid: string; newOid: string; ref: string }> = [];
    for (const packet of packets) {
      if (packet.kind === 'flush') break;
      if (packet.kind !== 'data') continue;
      const text = packet.payload.toString('utf8');
      const nul = text.indexOf('\0');
      const line = (nul >= 0 ? text.slice(0, nul) : text).replace(/\n$/, '');
      const parts = line.split(' ');
      if (parts.length >= 3) commands.push({ oldOid: parts[0], newOid: parts[1], ref: parts.slice(2).join(' ') });
    }
    const packBytes = rawBody.subarray(packStart);
    let unpackOk = true;
    let unpackDetail = 'ok';
    if (packBytes.length > 0) {
      try {
        const objects = readPack(packBytes);
        for (const [oid, object] of objects) {
          if (!repo.objects.has(oid)) repo.objects.set(oid, object);
        }
      } catch (err) {
        unpackOk = false;
        unpackDetail = err instanceof Error ? err.message : 'unpack failed';
      }
    }
    const reportLines: string[] = [`unpack ${unpackOk ? 'ok' : unpackDetail}\n`];
    for (const command of commands) {
      const current = repo.refs.get(command.ref);
      let ok = false;
      let reason = '';
      if (!unpackOk) {
        reason = 'unpack failed';
      } else if (command.newOid === ZERO_OID) {
        // Delete.
        if (current === undefined) reason = 'ref does not exist';
        else if (current !== command.oldOid && command.oldOid !== ZERO_OID) reason = 'stale info';
        else {
          repo.refs.delete(command.ref);
          ok = true;
        }
      } else {
        const object = repo.objects.get(command.newOid);
        if (!object) reason = 'object not found';
        else if (current === undefined) {
          if (command.oldOid !== ZERO_OID) reason = 'stale info';
          else {
            // Creating a ref: the new tip's closure must be present.
            const missing = [...reachableObjects(repo, [command.newOid])].filter((oid) => !repo.objects.has(oid));
            if (missing.length > 0) reason = 'missing objects';
            else {
              repo.refs.set(command.ref, command.newOid);
              ok = true;
            }
          }
        } else if (current !== command.oldOid) {
          reason = 'stale info';
        } else if (command.ref.startsWith('refs/heads/') && !isAncestor(repo, current, command.newOid)) {
          reason = 'non-fast-forward';
        } else {
          repo.refs.set(command.ref, command.newOid);
          ok = true;
        }
      }
      reportLines.push(ok ? `ok ${command.ref}\n` : `ng ${command.ref} ${reason}\n`);
    }
    const inner = Buffer.concat([encodePktLines(reportLines), PKT_FLUSH]);
    const body = Buffer.concat([pktLine(Buffer.concat([Buffer.from([1]), inner])), PKT_FLUSH]);
    res.writeHead(200, { 'content-type': 'application/x-git-receive-pack-result', 'content-length': body.length, 'x-github-request-id': requestId() });
    res.end(body);
    return true;
  }

  return false;
}

// ---------------------------------------------------------------------------
// GraphQL v4 (a small parser + executor for the documents gh sends)
// ---------------------------------------------------------------------------

type GqlValue =
  | { kind: 'var'; name: string }
  | { kind: 'string'; value: string }
  | { kind: 'int'; value: number }
  | { kind: 'bool'; value: boolean }
  | { kind: 'null' }
  | { kind: 'enum'; value: string }
  | { kind: 'list'; items: GqlValue[] }
  | { kind: 'object'; fields: Record<string, GqlValue> };

interface GqlField {
  kind: 'field';
  alias: string | null;
  name: string;
  args: Record<string, GqlValue>;
  selections: GqlSelection[];
}

interface GqlFragment {
  kind: 'fragment';
  typeCondition: string | null;
  selections: GqlSelection[];
}

type GqlSelection = GqlField | GqlFragment;

interface GqlOperation {
  kind: 'query' | 'mutation';
  name: string | null;
  variables: Record<string, { default?: unknown }>;
  selections: GqlSelection[];
}

function tokenizeGql(text: string): Array<{ kind: string; value: string }> {
  const tokens: Array<{ kind: string; value: string }> = [];
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === ' ' || ch === '\n' || ch === '\r' || ch === '\t' || ch === ',') {
      i += 1;
      continue;
    }
    if (ch === '#') {
      while (i < text.length && text[i] !== '\n') i += 1;
      continue;
    }
    if (ch === '.' && text.slice(i, i + 3) === '...') {
      tokens.push({ kind: 'punct', value: '...' });
      i += 3;
      continue;
    }
    if ('{}()[]:!=$'.includes(ch)) {
      tokens.push({ kind: 'punct', value: ch });
      i += 1;
      continue;
    }
    if (ch === '"') {
      let value = '';
      i += 1;
      while (i < text.length && text[i] !== '"') {
        if (text[i] === '\\' && i + 1 < text.length) {
          const esc = text[i + 1];
          value += esc === 'n' ? '\n' : esc === 't' ? '\t' : esc === 'r' ? '\r' : esc;
          i += 2;
        } else {
          value += text[i];
          i += 1;
        }
      }
      i += 1;
      tokens.push({ kind: 'string', value });
      continue;
    }
    if (ch === '-' || (ch >= '0' && ch <= '9')) {
      let value = '';
      while (i < text.length && /[0-9.eE+-]/.test(text[i])) {
        value += text[i];
        i += 1;
      }
      tokens.push({ kind: 'int', value });
      continue;
    }
    if (/[A-Za-z_]/.test(ch)) {
      let value = '';
      while (i < text.length && /[A-Za-z0-9_]/.test(text[i])) {
        value += text[i];
        i += 1;
      }
      tokens.push({ kind: 'name', value });
      continue;
    }
    throw new Error(`unexpected character ${JSON.stringify(ch)} in GraphQL document`);
  }
  return tokens;
}

class GqlParser {
  private tokens: Array<{ kind: string; value: string }>;
  private pos = 0;

  constructor(text: string) {
    this.tokens = tokenizeGql(text);
  }

  private peek(): { kind: string; value: string } | null {
    return this.tokens[this.pos] ?? null;
  }

  private next(): { kind: string; value: string } {
    const tok = this.tokens[this.pos];
    if (!tok) throw new Error('unexpected end of GraphQL document');
    this.pos += 1;
    return tok;
  }

  private expectPunct(value: string): void {
    const tok = this.next();
    if (tok.kind !== 'punct' || tok.value !== value) throw new Error(`expected ${value}, got ${tok.value}`);
  }

  private expectName(value?: string): string {
    const tok = this.next();
    if (tok.kind !== 'name' || (value !== undefined && tok.value !== value)) {
      throw new Error(`expected name ${value ?? ''}, got ${tok.value}`);
    }
    return tok.value;
  }

  parseDocument(): GqlOperation[] {
    const operations: GqlOperation[] = [];
    while (this.peek() !== null) {
      operations.push(this.parseOperation());
    }
    return operations;
  }

  private parseOperation(): GqlOperation {
    let kind: 'query' | 'mutation' = 'query';
    const tok = this.peek();
    if (tok?.kind === 'name' && (tok.value === 'query' || tok.value === 'mutation')) {
      kind = this.next().value as 'query' | 'mutation';
    }
    let name: string | null = null;
    if (this.peek()?.kind === 'name') name = this.next().value;
    const variables: Record<string, { default?: unknown }> = {};
    if (this.peek()?.value === '(') {
      this.next();
      while (this.peek()?.value !== ')') {
        this.expectPunct('$');
        const varName = this.expectName();
        this.expectPunct(':');
        this.parseType();
        if (this.peek()?.value === '=') {
          this.next();
          variables[varName] = { default: this.valueFrom(this.parseValue()) };
        } else {
          variables[varName] = {};
        }
      }
      this.expectPunct(')');
    }
    const selections = this.parseSelectionSet();
    return { kind, name, variables, selections };
  }

  private parseType(): void {
    if (this.peek()?.value === '[') {
      this.next();
      this.parseType();
      this.expectPunct(']');
    } else {
      this.expectName();
    }
    if (this.peek()?.value === '!') this.next();
  }

  private parseSelectionSet(): GqlSelection[] {
    this.expectPunct('{');
    const selections: GqlSelection[] = [];
    while (this.peek() !== null && this.peek()?.value !== '}') {
      selections.push(this.parseSelection());
    }
    this.expectPunct('}');
    return selections;
  }

  private parseSelection(): GqlSelection {
    if (this.peek()?.value === '...') {
      this.next();
      let typeCondition: string | null = null;
      if (this.peek()?.kind === 'name' && this.peek()?.value === 'on') {
        this.next();
        typeCondition = this.expectName();
      }
      return { kind: 'fragment', typeCondition, selections: this.parseSelectionSet() };
    }
    const first = this.expectName();
    let alias: string | null = null;
    let name = first;
    if (this.peek()?.value === ':') {
      this.next();
      alias = first;
      name = this.expectName();
    }
    const args: Record<string, GqlValue> = {};
    if (this.peek()?.value === '(') {
      this.next();
      while (this.peek()?.value !== ')') {
        const argName = this.expectName();
        this.expectPunct(':');
        args[argName] = this.parseValue();
      }
      this.expectPunct(')');
    }
    let selections: GqlSelection[] = [];
    if (this.peek()?.value === '{') selections = this.parseSelectionSet();
    return { kind: 'field', alias, name, args, selections };
  }

  private parseValue(): GqlValue {
    const tok = this.next();
    if (tok.kind === 'punct' && tok.value === '$') return { kind: 'var', name: this.expectName() };
    if (tok.kind === 'punct' && tok.value === '[') {
      const items: GqlValue[] = [];
      while (this.peek()?.value !== ']') items.push(this.parseValue());
      this.expectPunct(']');
      return { kind: 'list', items };
    }
    if (tok.kind === 'punct' && tok.value === '{') {
      const fields: Record<string, GqlValue> = {};
      while (this.peek()?.value !== '}') {
        const key = this.expectName();
        this.expectPunct(':');
        fields[key] = this.parseValue();
      }
      this.expectPunct('}');
      return { kind: 'object', fields };
    }
    if (tok.kind === 'string') return { kind: 'string', value: tok.value };
    if (tok.kind === 'int') return { kind: 'int', value: Number(tok.value) };
    if (tok.kind === 'name') {
      if (tok.value === 'true') return { kind: 'bool', value: true };
      if (tok.value === 'false') return { kind: 'bool', value: false };
      if (tok.value === 'null') return { kind: 'null' };
      return { kind: 'enum', value: tok.value };
    }
    throw new Error(`unexpected value token ${tok.value}`);
  }

  private valueFrom(value: GqlValue): unknown {
    switch (value.kind) {
      case 'string':
      case 'enum':
        return value.value;
      case 'int':
        return value.value;
      case 'bool':
        return value.value;
      case 'null':
        return null;
      case 'list':
        return value.items.map((item) => this.valueFrom(item));
      case 'object': {
        const out: Record<string, unknown> = {};
        for (const [k, v] of Object.entries(value.fields)) out[k] = this.valueFrom(v);
        return out;
      }
      default:
        return null;
    }
  }
}

// The schema: the fields each type offers (used for validation and introspection).
const GQL_SCHEMA: Record<string, string[]> = {
  Query: ['viewer', 'repository', 'node', '__type'],
  User: ['login', 'id', 'name', 'email'],
  Repository: ['id', 'databaseId', 'name', 'nameWithOwner', 'owner', 'defaultBranchRef', 'viewerPermission', 'hasIssuesEnabled', 'issue', 'issues', 'pullRequests', 'pullRequest'],
  Ref: ['name', 'target'],
  Issue: ['id', 'number', 'title', 'state', 'body'],
  IssueConnection: ['nodes', 'pageInfo'],
  PageInfo: ['hasNextPage', 'endCursor', 'hasPreviousPage', 'startCursor'],
  PullRequest: ['id', 'number', 'title', 'body', 'state', 'merged', 'headRefName', 'baseRefName', 'mergeable', 'files'],
  PullRequestConnection: ['nodes', 'pageInfo'],
  PullRequestChangedFileConnection: ['nodes', 'pageInfo'],
  PullRequestChangedFile: ['path', 'additions', 'deletions', 'changeType'],
  __Type: ['name', 'kind', 'fields', 'enumValues', 'description'],
  __Field: ['name', 'description'],
  __EnumValue: ['name', 'description'],
  Mutation: ['createIssue', 'closeIssue', 'createPullRequest', 'mergePullRequest', 'addComment'],
  CreateIssuePayload: ['issue', 'clientMutationId'],
  CloseIssuePayload: ['issue', 'clientMutationId'],
  CreatePullRequestPayload: ['pullRequest', 'clientMutationId'],
  MergePullRequestPayload: ['pullRequest', 'clientMutationId'],
  AddCommentPayload: ['commentEdge', 'clientMutationId'],
  IssueCommentEdge: ['node', 'cursor'],
  IssueComment: ['id', 'body'],
};

const GQL_ENUM_VALUES: Record<string, string[]> = {
  SearchType: ['ISSUE', 'REPOSITORY', 'USER', 'DISCUSSION', 'CODE', 'COMMIT', 'MILESTONE', 'WIKI'],
  IssueState: ['OPEN', 'CLOSED'],
  PullRequestState: ['OPEN', 'CLOSED', 'MERGED'],
  MergeableState: ['MERGEABLE', 'CONFLICTING', 'UNKNOWN'],
  RepositoryPermission: ['ADMIN', 'MAINTAIN', 'WRITE', 'TRIAGE', 'READ'],
  IssueOrderField: ['CREATED_AT', 'UPDATED_AT', 'COMMENTS'],
  OrderDirection: ['ASC', 'DESC'],
  PullRequestMergeMethod: ['MERGE', 'SQUASH', 'REBASE'],
};

interface GqlContext {
  errors: Array<{ message: string }>;
}

function gqlValue(value: GqlValue, variables: Record<string, unknown>): unknown {
  switch (value.kind) {
    case 'var':
      return variables[value.name] ?? null;
    case 'string':
    case 'enum':
      return value.value;
    case 'int':
      return value.value;
    case 'bool':
      return value.value;
    case 'null':
      return null;
    case 'list':
      return value.items.map((item) => gqlValue(item, variables));
    case 'object': {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value.fields)) out[k] = gqlValue(v, variables);
      return out;
    }
  }
}

function gqlArgs(field: GqlField, variables: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(field.args)) out[k] = gqlValue(v, variables);
  return out;
}

type GqlSource = Record<string, unknown> & { __typename: string };

function wrapRepo(repo: Repo): GqlSource {
  return { __typename: 'Repository', __repo: repo };
}

function wrapIssue(repo: Repo, issue: Issue): GqlSource {
  return { __typename: 'Issue', __repo: repo, __issue: issue };
}

function wrapPull(repo: Repo, pull: Pull): GqlSource {
  return { __typename: 'PullRequest', __repo: repo, __pull: pull };
}

function repoOf(source: GqlSource): Repo {
  return source.__repo as Repo;
}

function issueState(issue: Issue): string {
  return issue.state === 'open' ? 'OPEN' : 'CLOSED';
}

function pullState(pull: Pull): string {
  if (pull.merged) return 'MERGED';
  return pull.state === 'open' ? 'OPEN' : 'CLOSED';
}

function issueConnection(
  repo: Repo,
  issues: Issue[],
  first: number | null,
  after: string | null,
  direction: 'asc' | 'desc',
): GqlSource {
  let list = direction === 'asc' ? [...issues].sort((a, b) => a.seq - b.seq) : [...issues].sort((a, b) => b.seq - a.seq);
  if (after !== null && after !== undefined) {
    try {
      const text = Buffer.from(after, 'base64').toString('utf8');
      const num = parseInt(text.replace(/^issue:/, ''), 10);
      if (Number.isFinite(num)) {
        list = direction === 'asc' ? list.filter((i) => i.number > num) : list.filter((i) => i.number < num);
      }
    } catch {
      // An opaque cursor that does not decode is treated as the start.
    }
  }
  const total = list.length;
  const page = first === null || first === undefined ? list : list.slice(0, first);
  const endCursor = page.length > 0 ? Buffer.from(`issue:${page[page.length - 1].number}`, 'utf8').toString('base64') : null;
  return {
    __typename: 'IssueConnection',
    __nodes: page.map((i) => wrapIssue(repo, i)),
    __pageInfo: { __typename: 'PageInfo', hasNextPage: first !== null && first !== undefined ? total > first : false, endCursor },
  };
}

function resolveField(ctx: GqlContext, source: GqlSource, field: GqlField, variables: Record<string, unknown>): unknown {
  const typeName = source.__typename;
  const args = gqlArgs(field, variables);
  const known = GQL_SCHEMA[typeName] ?? [];
  if (!known.includes(field.name)) {
    ctx.errors.push({ message: `Cannot query field "${field.name}" on type "${typeName}".` });
    return null;
  }
  switch (typeName) {
    case 'Query': {
      if (field.name === 'viewer') return { __typename: 'User', login: VIEWER_LOGIN, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL };
      if (field.name === 'repository') {
        const owner = args.owner as string;
        const name = args.name as string;
        if (owner !== VIEWER_LOGIN) return null;
        const repo = getRepo(owner, name);
        return repo ? wrapRepo(repo) : null;
      }
      if (field.name === 'node') {
        const decoded = typeof args.id === 'string' ? decodeGlobalId(args.id) : null;
        if (!decoded) return null;
        if (decoded.kind === 'Repository') {
          const [owner, name] = decoded.key.split('/');
          const repo = getRepo(owner, name);
          return repo ? wrapRepo(repo) : null;
        }
        if (decoded.kind === 'Issue') {
          const [owner, name, num] = decoded.key.split(':');
          const repo = getRepo(owner, name);
          const issue = repo?.issues.find((i) => i.number === parseInt(num, 10));
          return repo && issue ? wrapIssue(repo, issue) : null;
        }
        if (decoded.kind === 'PullRequest') {
          const [owner, name, num] = decoded.key.split(':');
          const repo = getRepo(owner, name);
          const pull = repo?.pulls.find((p) => p.number === parseInt(num, 10));
          return repo && pull ? wrapPull(repo, pull) : null;
        }
        return null;
      }
      if (field.name === '__type') {
        const name = args.name as string;
        const fields = GQL_SCHEMA[name];
        const enumValues = GQL_ENUM_VALUES[name];
        if (!fields && !enumValues) return null;
        return {
          __typename: '__Type',
          __typeName: name,
          __fields: fields ?? [],
          __enumValues: enumValues ?? null,
        };
      }
      return null;
    }
    case 'User':
      return source[field.name] ?? null;
    case 'Repository': {
      const repo = repoOf(source);
      if (field.name === 'id') return globalId('Repository', `${repo.owner}/${repo.name}`);
      if (field.name === 'databaseId') return repo.id;
      if (field.name === 'name') return repo.name;
      if (field.name === 'nameWithOwner') return `${repo.owner}/${repo.name}`;
      if (field.name === 'owner') return { __typename: 'User', login: repo.owner, id: VIEWER_ID, name: VIEWER_NAME, email: VIEWER_EMAIL };
      if (field.name === 'defaultBranchRef') {
        const tip = repo.refs.get(`refs/heads/${repo.defaultBranch}`);
        return tip ? { __typename: 'Ref', name: repo.defaultBranch, target: tip } : null;
      }
      if (field.name === 'viewerPermission') return 'ADMIN';
      if (field.name === 'hasIssuesEnabled') return true;
      if (field.name === 'issue') {
        const issue = repo.issues.find((i) => i.number === (args.number as number));
        return issue ? wrapIssue(repo, issue) : null;
      }
      if (field.name === 'issues') {
        let list = [...repo.issues];
        const states = args.states as string[] | undefined;
        if (Array.isArray(states) && states.length > 0) {
          const wanted = new Set(states.map((s) => s.toLowerCase()));
          list = list.filter((i) => wanted.has(i.state));
        }
        const orderBy = args.orderBy as { field?: string; direction?: string } | undefined;
        const direction: 'asc' | 'desc' = orderBy?.direction === 'ASC' ? 'asc' : 'desc';
        const first = typeof args.first === 'number' ? args.first : null;
        const after = typeof args.after === 'string' ? args.after : null;
        return issueConnection(repo, list, first, after, direction);
      }
      if (field.name === 'pullRequest') {
        const pull = repo.pulls.find((p) => p.number === (args.number as number));
        return pull ? wrapPull(repo, pull) : null;
      }
      if (field.name === 'pullRequests') {
        let list = [...repo.pulls].sort((a, b) => b.seq - a.seq);
        const first = typeof args.first === 'number' ? args.first : null;
        if (first !== null) list = list.slice(0, first);
        return { __typename: 'PullRequestConnection', __nodes: list.map((p) => wrapPull(repo, p)), __pageInfo: { __typename: 'PageInfo', hasNextPage: false, endCursor: null } };
      }
      return null;
    }
    case 'Ref':
      return source[field.name] ?? null;
    case 'Issue': {
      const issue = source.__issue as Issue;
      const repo = repoOf(source);
      if (field.name === 'id') return globalId('Issue', `${repo.owner}/${repo.name}:${issue.number}`);
      if (field.name === 'number') return issue.number;
      if (field.name === 'title') return issue.title;
      if (field.name === 'state') return issueState(issue);
      if (field.name === 'body') return issue.body;
      return null;
    }
    case 'IssueConnection': {
      if (field.name === 'nodes') return (source.__nodes as GqlSource[]) ?? [];
      if (field.name === 'pageInfo') return source.__pageInfo as GqlSource;
      return null;
    }
    case 'PageInfo':
      return source[field.name] ?? null;
    case 'PullRequest': {
      const pull = source.__pull as Pull;
      const repo = repoOf(source);
      if (field.name === 'id') return globalId('PullRequest', `${repo.owner}/${repo.name}:${pull.number}`);
      if (field.name === 'number') return pull.number;
      if (field.name === 'title') return pull.title;
      if (field.name === 'body') return pull.body;
      if (field.name === 'state') return pullState(pull);
      if (field.name === 'merged') return pull.merged;
      if (field.name === 'headRefName') return pull.head;
      if (field.name === 'baseRefName') return pull.base;
      if (field.name === 'mergeable') {
        if (pull.state !== 'open') return 'UNKNOWN';
        return pullMergeable(repo, pull) ? 'MERGEABLE' : 'CONFLICTING';
      }
      if (field.name === 'files') {
        const files = pullFiles(repo, pull);
        const first = typeof args.first === 'number' ? args.first : null;
        const page = first === null ? files : files.slice(0, first);
        return {
          __typename: 'PullRequestChangedFileConnection',
          __nodes: page.map((f) => ({ __typename: 'PullRequestChangedFile', path: f.filename, additions: f.additions, deletions: f.deletions, changeType: f.status })),
          __pageInfo: { __typename: 'PageInfo', hasNextPage: false, endCursor: null },
        };
      }
      return null;
    }
    case 'PullRequestConnection': {
      if (field.name === 'nodes') return (source.__nodes as GqlSource[]) ?? [];
      if (field.name === 'pageInfo') return source.__pageInfo as GqlSource;
      return null;
    }
    case 'PullRequestChangedFileConnection': {
      if (field.name === 'nodes') return (source.__nodes as GqlSource[]) ?? [];
      if (field.name === 'pageInfo') return source.__pageInfo as GqlSource;
      return null;
    }
    case 'PullRequestChangedFile':
      return source[field.name] ?? null;
    case '__Type': {
      if (field.name === 'name') return source.__typeName as string;
      if (field.name === 'kind') return (source.__enumValues as string[] | null) !== null ? 'ENUM' : 'OBJECT';
      if (field.name === 'fields') {
        return (source.__fields as string[]).map((name) => ({ __typename: '__Field', name }));
      }
      if (field.name === 'enumValues') {
        const values = source.__enumValues as string[] | null;
        return values === null ? null : values.map((name) => ({ __typename: '__EnumValue', name }));
      }
      return null;
    }
    case '__Field':
    case '__EnumValue':
      return source[field.name] ?? null;
    case 'Mutation': {
      const input = (args.input ?? {}) as Record<string, unknown>;
      if (field.name === 'createIssue') {
        const decoded = typeof input.repositoryId === 'string' ? decodeGlobalId(input.repositoryId) : null;
        if (!decoded || decoded.kind !== 'Repository') {
          ctx.errors.push({ message: 'createIssue: unknown repositoryId' });
          return null;
        }
        const [owner, name] = decoded.key.split('/');
        const repo = getRepo(owner, name);
        if (!repo) {
          ctx.errors.push({ message: 'createIssue: unknown repository' });
          return null;
        }
        const created = createIssueRecord(repo, String(input.title ?? ''), typeof input.body === 'string' ? input.body : '', []);
        if ('error' in created) {
          ctx.errors.push({ message: created.error });
          return null;
        }
        return { __typename: 'CreateIssuePayload', __issue: wrapIssue(repo, created) };
      }
      if (field.name === 'closeIssue') {
        const decoded = typeof input.issueId === 'string' ? decodeGlobalId(input.issueId) : null;
        if (!decoded || decoded.kind !== 'Issue') {
          ctx.errors.push({ message: 'closeIssue: unknown issueId' });
          return null;
        }
        const [fullName, num] = decoded.key.split(':');
        const [owner, name] = fullName.split('/');
        const repo = getRepo(owner, name);
        const issue = repo?.issues.find((i) => i.number === parseInt(num, 10));
        if (!repo || !issue) {
          ctx.errors.push({ message: 'closeIssue: unknown issue' });
          return null;
        }
        issue.state = 'closed';
        return { __typename: 'CloseIssuePayload', __issue: wrapIssue(repo, issue) };
      }
      if (field.name === 'createPullRequest') {
        const decoded = typeof input.repositoryId === 'string' ? decodeGlobalId(input.repositoryId) : null;
        if (!decoded || decoded.kind !== 'Repository') {
          ctx.errors.push({ message: 'createPullRequest: unknown repositoryId' });
          return null;
        }
        const [owner, name] = decoded.key.split('/');
        const repo = getRepo(owner, name);
        if (!repo) {
          ctx.errors.push({ message: 'createPullRequest: unknown repository' });
          return null;
        }
        const created = createPullRecord(
          repo,
          String(input.title ?? ''),
          typeof input.body === 'string' ? input.body : '',
          String(input.headRefName ?? ''),
          String(input.baseRefName ?? ''),
        );
        if ('error' in created) {
          ctx.errors.push({ message: created.error });
          return null;
        }
        return { __typename: 'CreatePullRequestPayload', __pull: wrapPull(repo, created) };
      }
      if (field.name === 'mergePullRequest') {
        const decoded = typeof input.pullRequestId === 'string' ? decodeGlobalId(input.pullRequestId) : null;
        if (!decoded || decoded.kind !== 'PullRequest') {
          ctx.errors.push({ message: 'mergePullRequest: unknown pullRequestId' });
          return null;
        }
        const [fullName, num] = decoded.key.split(':');
        const [owner, name] = fullName.split('/');
        const repo = getRepo(owner, name);
        const pull = repo?.pulls.find((p) => p.number === parseInt(num, 10));
        if (!repo || !pull) {
          ctx.errors.push({ message: 'mergePullRequest: unknown pull request' });
          return null;
        }
        const sha = mergePullRequest(repo, pull);
        if (sha === null) {
          ctx.errors.push({ message: 'mergePullRequest: merge conflict' });
          return null;
        }
        return { __typename: 'MergePullRequestPayload', __pull: wrapPull(repo, pull) };
      }
      if (field.name === 'addComment') {
        const decoded = typeof input.subjectId === 'string' ? decodeGlobalId(input.subjectId) : null;
        if (!decoded || decoded.kind !== 'Issue') {
          ctx.errors.push({ message: 'addComment: unknown subjectId' });
          return null;
        }
        const [fullName, num] = decoded.key.split(':');
        const [owner, name] = fullName.split('/');
        const repo = getRepo(owner, name);
        const issue = repo?.issues.find((i) => i.number === parseInt(num, 10));
        if (!repo || !issue) {
          ctx.errors.push({ message: 'addComment: unknown issue' });
          return null;
        }
        commentIdCounter += 1;
        const comment: IssueComment = { id: commentIdCounter, body: String(input.body ?? ''), user: VIEWER_LOGIN };
        const list = repo.comments.get(issue.number) ?? [];
        list.push(comment);
        repo.comments.set(issue.number, list);
        const nodeId = globalId('IssueComment', `${owner}/${name}:${issue.number}:${comment.id}`);
        return {
          __typename: 'AddCommentPayload',
          __commentEdge: { __typename: 'IssueCommentEdge', __node: { __typename: 'IssueComment', id: nodeId, body: comment.body } },
        };
      }
      return null;
    }
    case 'CreateIssuePayload':
    case 'CloseIssuePayload':
      if (field.name === 'issue') return source.__issue as GqlSource;
      return null;
    case 'CreatePullRequestPayload':
    case 'MergePullRequestPayload':
      if (field.name === 'pullRequest') return source.__pull as GqlSource;
      return null;
    case 'AddCommentPayload':
      if (field.name === 'commentEdge') return source.__commentEdge as GqlSource;
      return null;
    case 'IssueCommentEdge':
      if (field.name === 'node') return source.__node as GqlSource;
      return null;
    case 'IssueComment':
      return source[field.name] ?? null;
    default:
      return null;
  }
}

function executeSelections(
  ctx: GqlContext,
  source: GqlSource,
  selections: GqlSelection[],
  variables: Record<string, unknown>,
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const selection of selections) {
    if (selection.kind === 'fragment') {
      if (selection.typeCondition !== null && selection.typeCondition !== source.__typename) continue;
      Object.assign(out, executeSelections(ctx, source, selection.selections, variables));
      continue;
    }
    const value = resolveField(ctx, source, selection, variables);
    const key = selection.alias ?? selection.name;
    if (value === null || value === undefined) {
      out[key] = null;
    } else if (Array.isArray(value)) {
      out[key] = value.map((item) =>
        item !== null && typeof item === 'object' && '__typename' in (item as Record<string, unknown>)
          ? executeSelections(ctx, item as GqlSource, selection.selections, variables)
          : item,
      );
    } else if (typeof value === 'object' && '__typename' in (value as Record<string, unknown>)) {
      out[key] = executeSelections(ctx, value as GqlSource, selection.selections, variables);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function executeOperation(operation: GqlOperation, variables: Record<string, unknown>): { data: Record<string, unknown>; errors?: Array<{ message: string }> } {
  const ctx: GqlContext = { errors: [] };
  const root: GqlSource = operation.kind === 'mutation' ? { __typename: 'Mutation' } : { __typename: 'Query' };
  const data = executeSelections(ctx, root, operation.selections, variables);
  if (ctx.errors.length > 0) return { data, errors: ctx.errors };
  return { data };
}

function handleGraphQL(req: IncomingMessage, res: ServerResponse, rawBody: Buffer): boolean {
  if (!isAuthed(req)) {
    sendJson(res, 401, { message: 'Requires authentication' });
    return true;
  }
  let parsed: unknown;
  try {
    parsed = parseJsonBody(rawBody);
  } catch {
    sendError(res, 400, 'Problems parsing JSON');
    return true;
  }
  const runOne = (entry: unknown): Record<string, unknown> => {
    if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) {
      return { data: {}, errors: [{ message: 'Invalid GraphQL request' }] };
    }
    const query = (entry as Record<string, unknown>).query;
    const variables = (entry as Record<string, unknown>).variables;
    if (typeof query !== 'string') return { data: {}, errors: [{ message: 'No query provided' }] };
    let operations: GqlOperation[];
    try {
      operations = new GqlParser(query).parseDocument();
    } catch (err) {
      return { data: {}, errors: [{ message: err instanceof Error ? err.message : 'GraphQL syntax error' }] };
    }
    const operation = operations[0];
    if (!operation) return { data: {}, errors: [{ message: 'Empty document' }] };
    const vars = (variables !== null && typeof variables === 'object' && !Array.isArray(variables) ? variables : {}) as Record<string, unknown>;
    return executeOperation(operation, vars);
  };
  if (Array.isArray(parsed)) {
    sendJson(res, 200, parsed.map((entry) => runOne(entry)));
    return true;
  }
  sendJson(res, 200, runOne(parsed));
  return true;
}

// ---------------------------------------------------------------------------
// MCP over streamable HTTP (2026-07-28 discover era + the 2025-11-25 handshake)
// ---------------------------------------------------------------------------

interface McpToolDef {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}

const MCP_TOOLS: McpToolDef[] = [
  {
    name: 'create_repo',
    description: 'Create a repository owned by the authenticated user.',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'The repository name.' },
        description: { type: 'string', description: 'A short description of the repository.' },
        private: { type: 'boolean', description: 'Whether the repository is private.' },
        owner: { type: 'string', description: 'The owner login (defaults to the authenticated user).' },
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
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
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
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The issue title.' },
        body: { type: 'string', description: 'The issue body.' },
      },
      required: ['owner', 'repo', 'title'],
    },
  },
  {
    name: 'list_issues',
    description: 'List the issues of a repository.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        state: { type: 'string', description: 'Filter by state: open, closed or all.' },
      },
      required: ['owner', 'repo'],
    },
  },
  {
    name: 'create_pull_request',
    description: 'Open a pull request from a head branch into a base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        title: { type: 'string', description: 'The pull request title.' },
        body: { type: 'string', description: 'The pull request body.' },
        head: { type: 'string', description: 'The head branch name.' },
        base: { type: 'string', description: 'The base branch name.' },
      },
      required: ['owner', 'repo', 'title', 'head', 'base'],
    },
  },
  {
    name: 'merge_pull_request',
    description: 'Merge a pull request (squash) into its base branch.',
    inputSchema: {
      type: 'object',
      properties: {
        owner: { type: 'string', description: 'The repository owner login.' },
        repo: { type: 'string', description: 'The repository name.' },
        pull_number: { type: 'integer', description: 'The pull request number.' },
      },
      required: ['owner', 'repo', 'pull_number'],
    },
  },
];

function mcpOk(result: unknown): Record<string, unknown> {
  return { content: [{ type: 'text', text: JSON.stringify(result) }], structuredContent: result };
}

function mcpFail(message: string): Record<string, unknown> {
  return { content: [{ type: 'text', text: message }], isError: true };
}

function pickArg(args: Record<string, unknown>, ...names: string[]): unknown {
  for (const name of names) {
    if (args[name] !== undefined && args[name] !== null) return args[name];
  }
  return undefined;
}

function mcpResolveRepo(args: Record<string, unknown>): Repo | { error: string } {
  const owner = pickArg(args, 'owner', 'owner_login', 'org', 'login', 'user_login');
  const repoName = pickArg(args, 'repo', 'repository', 'repo_name', 'repository_name');
  const fullName = pickArg(args, 'full_name', 'repo_full_name', 'fullName');
  let ownerStr = typeof owner === 'string' ? owner : VIEWER_LOGIN;
  let repoStr = typeof repoName === 'string' ? repoName : '';
  if (repoStr === '' && typeof fullName === 'string' && fullName.includes('/')) {
    const [o, r] = fullName.split('/', 2);
    ownerStr = o;
    repoStr = r;
  }
  if (ownerStr !== VIEWER_LOGIN) return { error: 'Repository not found' };
  const repo = getRepo(ownerStr, repoStr);
  if (!repo) return { error: 'Repository not found' };
  return repo;
}

function mcpCallTool(name: string, args: Record<string, unknown>): Record<string, unknown> {
  if (name === 'create_repo') {
    const repoName = pickArg(args, 'name', 'repo', 'repository', 'repository_name', 'repo_name');
    if (typeof repoName !== 'string' || repoName === '') return mcpFail('create_repo: "name" is required');
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(repoName)) return mcpFail('create_repo: invalid repository name');
    if (getRepo(VIEWER_LOGIN, repoName)) return mcpFail('create_repo: repository already exists');
    const repo = createRepoRecord(
      VIEWER_LOGIN,
      repoName,
      typeof pickArg(args, 'description', 'about', 'summary', 'body') === 'string' ? (pickArg(args, 'description', 'about', 'summary', 'body') as string) : '',
      pickArg(args, 'private', 'is_private') === true,
    );
    return mcpOk(repoObject(repo));
  }
  if (name === 'get_repo') {
    const resolved = mcpResolveRepo(args);
    if ('error' in resolved) return mcpFail(`get_repo: ${resolved.error}`);
    return mcpOk(repoObject(resolved));
  }
  if (name === 'create_issue') {
    const resolved = mcpResolveRepo(args);
    if ('error' in resolved) return mcpFail(`create_issue: ${resolved.error}`);
    const title = pickArg(args, 'title', 'issue_title', 'subject');
    if (typeof title !== 'string' || title === '') return mcpFail('create_issue: "title" is required');
    const body = pickArg(args, 'body', 'issue_body', 'description', 'content', 'text');
    const created = createIssueRecord(resolved, title, typeof body === 'string' ? body : '', []);
    if ('error' in created) return mcpFail(`create_issue: ${created.error}`);
    return mcpOk(issueObject(resolved, created));
  }
  if (name === 'list_issues') {
    const resolved = mcpResolveRepo(args);
    if ('error' in resolved) return mcpFail(`list_issues: ${resolved.error}`);
    const state = pickArg(args, 'state', 'status');
    const stateStr = typeof state === 'string' ? state : 'open';
    let list = [...resolved.issues];
    if (stateStr !== 'all') list = list.filter((i) => i.state === stateStr);
    list.sort((a, b) => b.seq - a.seq);
    const result = { issues: list.map((i) => issueObject(resolved, i)) };
    return mcpOk(result);
  }
  if (name === 'create_pull_request') {
    const resolved = mcpResolveRepo(args);
    if ('error' in resolved) return mcpFail(`create_pull_request: ${resolved.error}`);
    const title = pickArg(args, 'title', 'pr_title', 'pull_request_title', 'subject');
    const head = pickArg(args, 'head', 'head_ref', 'head_branch', 'source_branch', 'branch');
    const base = pickArg(args, 'base', 'base_ref', 'base_branch', 'target_branch');
    if (typeof title !== 'string' || title === '') return mcpFail('create_pull_request: "title" is required');
    if (typeof head !== 'string' || head === '') return mcpFail('create_pull_request: "head" is required');
    if (typeof base !== 'string' || base === '') return mcpFail('create_pull_request: "base" is required');
    const body = pickArg(args, 'body', 'description', 'content', 'text');
    const created = createPullRecord(resolved, title, typeof body === 'string' ? body : '', head, base);
    if ('error' in created) return mcpFail(`create_pull_request: ${created.error}`);
    return mcpOk(pullObject(resolved, created));
  }
  if (name === 'merge_pull_request') {
    const resolved = mcpResolveRepo(args);
    if ('error' in resolved) return mcpFail(`merge_pull_request: ${resolved.error}`);
    const num = pickArg(args, 'pull_number', 'pull_request_number', 'pr_number', 'number', 'issue_number', 'index');
    const pullNumber = typeof num === 'number' ? num : typeof num === 'string' && /^\d+$/.test(num) ? parseInt(num, 10) : NaN;
    if (!Number.isFinite(pullNumber)) return mcpFail('merge_pull_request: "pull_number" is required');
    const pull = resolved.pulls.find((p) => p.number === pullNumber);
    if (!pull) return mcpFail('merge_pull_request: pull request not found');
    if (pull.state !== 'open') return mcpFail('merge_pull_request: pull request is already closed');
    const sha = mergePullRequest(resolved, pull);
    if (sha === null) return mcpFail('merge_pull_request: merge conflict');
    return mcpOk({ ...pullObject(resolved, pull), sha });
  }
  return mcpFail(`Unknown tool: ${name}`);
}

function mcpRpcError(id: unknown, code: number, message: string): Record<string, unknown> {
  return { jsonrpc: '2.0', id: id ?? null, error: { code, message } };
}

function handleMcp(req: IncomingMessage, res: ServerResponse, rawBody: Buffer): boolean {
  if (!isAuthed(req)) {
    sendJson(res, 401, { jsonrpc: '2.0', id: null, error: { code: -32000, message: 'Unauthorized' } });
    return true;
  }
  let parsed: unknown;
  try {
    parsed = parseJsonBody(rawBody);
  } catch {
    sendJson(res, 400, mcpRpcError(null, -32700, 'Parse error'));
    return true;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    sendJson(res, 200, mcpRpcError(null, -32600, 'Invalid Request'));
    return true;
  }
  const request = parsed as Record<string, unknown>;
  const id = request.id ?? null;
  const isNotification = request.id === undefined;
  const method = request.method;
  if (typeof method !== 'string') {
    sendJson(res, 200, mcpRpcError(id, -32600, 'Invalid Request'));
    return true;
  }
  // Notifications get a 202 with no body.
  if (isNotification) {
    sendEmpty(res, 202);
    return true;
  }
  const params = (request.params !== null && typeof request.params === 'object' && !Array.isArray(request.params) ? request.params : {}) as Record<string, unknown>;
  const extraHeaders: Record<string, string> = {};

  if (method === 'server/discover') {
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        supportedVersions: ['2026-07-28'],
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        _meta: { 'io.modelcontextprotocol/serverInfo': { name: SERVER_NAME, version: SERVER_VERSION } },
      },
    }, extraHeaders);
    return true;
  }
  if (method === 'initialize') {
    const offered = params.protocolVersion;
    const known = ['2026-07-28', '2025-11-25', '2025-06-18', '2025-03-26', '2024-11-05'];
    const negotiated = typeof offered === 'string' && known.includes(offered) ? offered : '2025-11-25';
    extraHeaders['mcp-session-id'] = 'mcp-session-1';
    sendJson(res, 200, {
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: negotiated,
        capabilities: { tools: {} },
        serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
      },
    }, extraHeaders);
    return true;
  }
  if (method === 'tools/list') {
    sendJson(res, 200, { jsonrpc: '2.0', id, result: { tools: MCP_TOOLS } });
    return true;
  }
  if (method === 'tools/call') {
    const toolName = params.name;
    const toolArgs = (params.arguments !== null && typeof params.arguments === 'object' && !Array.isArray(params.arguments) ? params.arguments : {}) as Record<string, unknown>;
    if (typeof toolName !== 'string' || !MCP_TOOLS.some((t) => t.name === toolName)) {
      sendJson(res, 200, mcpRpcError(id, -32602, `Unknown tool: ${String(toolName ?? '')}`));
      return true;
    }
    const result = mcpCallTool(toolName, toolArgs);
    sendJson(res, 200, { jsonrpc: '2.0', id, result });
    return true;
  }
  sendJson(res, 200, mcpRpcError(id, -32601, `Method not found: ${method}`));
  return true;
}

// ---------------------------------------------------------------------------
// router
// ---------------------------------------------------------------------------

/** Build the server. It binds nothing until the caller listens. */
export function createApp(): Server {
  return createServer(async (req: IncomingMessage, res: ServerResponse) => {
    try {
      const url = urlOf(req);
      const path = url.pathname;
      const method = req.method ?? 'GET';
      const needsBody = method === 'POST' || method === 'PUT' || method === 'PATCH' || method === 'DELETE';
      const rawBody = needsBody ? await readBody(req) : Buffer.alloc(0);

      if (method === 'GET' && path === '/healthz') {
        sendJson(res, 200, { ok: true });
        return;
      }
      if (method === 'POST' && path === '/api/graphql') {
        handleGraphQL(req, res, rawBody);
        return;
      }
      if (method === 'POST' && path === '/mcp') {
        handleMcp(req, res, rawBody);
        return;
      }
      if (path.startsWith('/api/v3')) {
        if (handleRest(req, res, path, url, rawBody)) return;
      }
      if (handleGit(req, res, path, url, rawBody)) return;
      sendJson(res, 404, { message: 'Not Found' });
    } catch (err) {
      // A bad request must never take the server down with it.
      if (!res.headersSent) {
        sendJson(res, 500, { message: err instanceof Error ? err.message : 'Internal error' });
      } else {
        try {
          res.end();
        } catch {
          // Already ending; nothing more to do.
        }
      }
    }
  });
}
