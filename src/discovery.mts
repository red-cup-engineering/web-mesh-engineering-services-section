// mesh/discovery.ts — LAN peer discovery + Kademlia routing table.
//
// Two independent mechanisms, both pure transport:
//   • Kademlia (XOR metric, k-buckets, iterative findNode). nodeId = sha-256(identity).
//   • mDNS / DNS-SD (RFC 6762 / RFC 6763) over multicast UDP 224.0.0.251:5353.
//     Includes a minimal DNS wire-format codec (RFC 1035) for PTR/SRV/TXT/A records.
//
// The dgram socket is best-effort: if multicast fails (CI, container) discovery
// degrades to an in-memory routing table and emits "error" once; it never throws.

import * as crypto from "node:crypto";
import * as dgram from "node:dgram";
import { EventEmitter } from "node:events";

const MDNS_ADDR = "224.0.0.251";
const MDNS_PORT = 5353;
const ID_BYTES = 32;
const ID_BITS = ID_BYTES * 8;
const DEFAULT_K = 20;

// ── Kademlia id arithmetic ────────────────────────────────────────────────────

/** sha-256 of an arbitrary identity → a 32-byte node id buffer. */
export function sha256(identity?: string | Buffer): Buffer {
  const input = identity ?? crypto.randomBytes(ID_BYTES);
  return crypto.createHash("sha256").update(input).digest();
}

/** XOR distance metric d(a,b) = a ⊕ b as a 32-byte Buffer. */
export function xorDistance(a: Buffer, b: Buffer): Buffer {
  const x = Buffer.allocUnsafe(ID_BYTES);
  for (let i = 0; i < ID_BYTES; i++) x[i] = (a[i] ?? 0) ^ (b[i] ?? 0);
  return x;
}

/** Compare two XOR-distance buffers (big-endian). <0 = a nearer, >0 = a farther. */
export function compareDistance(a: Buffer, b: Buffer): number {
  for (let i = 0; i < ID_BYTES; i++) {
    if (a[i] !== b[i]) return (a[i] ?? 0) - (b[i] ?? 0);
  }
  return 0;
}

/** Index of the k-bucket a peer falls in relative to `self` (⌊log2 XOR⌋). -1 = self. */
export function bucketIndex(self: Buffer, peer: Buffer): number {
  for (let i = 0; i < ID_BYTES; i++) {
    const x = (self[i] ?? 0) ^ (peer[i] ?? 0);
    if (x !== 0) {
      let bit = 7;
      for (let m = 0x80; m; m >>= 1, bit--) if (x & m) break;
      return ID_BITS - 1 - (i * 8 + (7 - bit));
    }
  }
  return -1;
}

// ── RoutingTable (k-buckets) ──────────────────────────────────────────────────

export type KadContact = { id: Buffer; [key: string]: unknown };

export class RoutingTable {
  readonly selfId: Buffer;
  readonly k: number;
  readonly buckets: Map<number, KadContact[]>;

  constructor(selfId: Buffer, opts: { k?: number } = {}) {
    if (!Buffer.isBuffer(selfId) || selfId.length !== ID_BYTES) {
      throw new TypeError("RoutingTable: selfId must be a 32-byte Buffer");
    }
    this.selfId = selfId;
    this.k = opts.k ?? DEFAULT_K;
    this.buckets = new Map();
  }

  private _bucket(id: Buffer): KadContact[] | null {
    const idx = bucketIndex(this.selfId, id);
    if (idx < 0) return null;
    let b = this.buckets.get(idx);
    if (!b) { b = []; this.buckets.set(idx, b); }
    return b;
  }

  has(id: Buffer): boolean {
    const b = this._bucket(id);
    return !!b && b.some((c) => c.id.equals(id));
  }

  insert(contact: KadContact, opts: { ping?: (c: KadContact) => boolean } = {}): "self" | "updated" | "added" | "evicted" | "rejected" {
    if (!contact || !Buffer.isBuffer(contact.id) || contact.id.length !== ID_BYTES) {
      throw new TypeError("insert: contact.id must be a 32-byte Buffer");
    }
    if (contact.id.equals(this.selfId)) return "self";
    const b = this._bucket(contact.id);
    if (!b) return "self";
    const at = b.findIndex((c) => c.id.equals(contact.id));
    if (at !== -1) {
      const [existing] = b.splice(at, 1);
      b.push({ ...existing, ...contact, seen: Date.now() }); // law-allow: wall-clock-as-data — peer last-seen testimony, not ordering
      return "updated";
    }
    if (b.length < this.k) {
      b.push({ ...contact, seen: Date.now() }); // law-allow: wall-clock-as-data — peer last-seen testimony, not ordering
      return "added";
    }
    const head = b[0]!;
    if (opts.ping && !opts.ping(head)) {
      b.shift();
      b.push({ ...contact, seen: Date.now() }); // law-allow: wall-clock-as-data — peer last-seen testimony, not ordering
      return "evicted";
    }
    return "rejected";
  }

  remove(id: Buffer): boolean {
    const b = this._bucket(id);
    if (!b) return false;
    const at = b.findIndex((c) => c.id.equals(id));
    if (at === -1) return false;
    b.splice(at, 1);
    return true;
  }

  contacts(): KadContact[] {
    const out: KadContact[] = [];
    for (const b of this.buckets.values()) out.push(...b);
    return out;
  }

  get size(): number {
    let n = 0;
    for (const b of this.buckets.values()) n += b.length;
    return n;
  }

  closest(targetId: Buffer, count = this.k): KadContact[] {
    return this.contacts()
      .map((c) => ({ c, d: xorDistance(c.id, targetId) }))
      .sort((a, b) => compareDistance(a.d, b.d))
      .slice(0, count)
      .map(({ c }) => c);
  }
}

/**
 * findNode(targetId, opts) — Kademlia iterative node lookup (§2.3).
 * `query(contact, targetId) => Promise<KadContact[]>` is the injected transport probe.
 */
export async function findNode(
  targetId: Buffer,
  opts: {
    table: RoutingTable;
    query: (contact: KadContact, target: Buffer) => Promise<KadContact[]>;
    k?: number;
    alpha?: number;
    signal?: AbortSignal;
  },
): Promise<KadContact[]> {
  const { table, query, k = table.k, alpha = 3, signal } = opts;
  if (!table) throw new TypeError("findNode: a RoutingTable is required");
  if (typeof query !== "function") throw new TypeError("findNode: a query function is required");

  const key = (id: Buffer) => id.toString("hex");
  const seen = new Map<string, KadContact>();
  const queried = new Set<string>();
  for (const c of table.closest(targetId, k)) seen.set(key(c.id), c);

  const nearest = () =>
    [...seen.values()]
      .map((c) => ({ c, d: xorDistance(c.id, targetId) }))
      .sort((a, b) => compareDistance(a.d, b.d))
      .map(({ c }) => c);

  let closestBefore: Buffer | null = null;
  for (let round = 0; round < ID_BITS; round++) {
    if (signal?.aborted) break;
    const front = nearest();
    const best = front[0]?.id ?? null;
    if (closestBefore && best && best.equals(closestBefore)) break;
    closestBefore = best ?? closestBefore;

    const batch = front.filter((c) => !queried.has(key(c.id))).slice(0, alpha);
    if (batch.length === 0) break;

    const results = await Promise.allSettled(batch.map(async (c) => {
      queried.add(key(c.id));
      return query(c, targetId);
    }));
    for (const r of results) {
      if (r.status !== "fulfilled" || !Array.isArray(r.value)) continue;
      for (const c of r.value) {
        if (!c || !Buffer.isBuffer(c.id) || c.id.length !== ID_BYTES) continue;
        if (!seen.has(key(c.id))) seen.set(key(c.id), c);
        try { table.insert(c); } catch { /* ignore bad metadata */ }
      }
    }
  }
  return nearest().slice(0, k);
}

// ── DNS wire codec (RFC 1035) ─────────────────────────────────────────────────

export const DNS_TYPE = { A: 1, PTR: 12, TXT: 16, SRV: 33, AAAA: 28, ANY: 255 } as const;
const DNS_CLASS_IN = 1;
const TYPE_NAME = Object.fromEntries(Object.entries(DNS_TYPE).map(([k, v]) => [v, k])) as Record<number, string>;

function encodeName(name: string): Buffer {
  const labels = String(name).replace(/\.$/, "").split(".").filter(Boolean);
  const parts: Buffer[] = [];
  for (const label of labels) {
    const b = Buffer.from(label, "utf8");
    if (b.length > 63) throw new RangeError(`DNS label too long: ${label}`);
    parts.push(Buffer.from([b.length]), b);
  }
  parts.push(Buffer.from([0]));
  return Buffer.concat(parts);
}

function readName(buf: Buffer, offset: number): { name: string; offset: number } {
  const labels: string[] = [];
  let pos = offset;
  let jumped = false;
  let next = offset;
  let safety = 0;
  while (pos < buf.length) {
    if (++safety > 128) throw new Error("DNS name: too many labels / pointer loop");
    const len = buf[pos]!;
    if (len === 0) { if (!jumped) next = pos + 1; break; }
    if ((len & 0xc0) === 0xc0) {
      const ptr = ((len & 0x3f) << 8) | buf[pos + 1]!;
      if (!jumped) next = pos + 2;
      jumped = true;
      if (ptr >= pos) throw new Error("DNS name: forward/self pointer");
      pos = ptr; continue;
    }
    pos += 1;
    labels.push(buf.toString("utf8", pos, pos + len));
    pos += len;
    if (!jumped) next = pos;
  }
  return { name: labels.join("."), offset: next };
}

function encodeTxt(txt: string[] | Record<string, string>): Buffer {
  let strings: string[];
  if (Array.isArray(txt)) strings = txt;
  else if (txt && typeof txt === "object") strings = Object.entries(txt).map(([k, v]) => `${k}=${v}`);
  else strings = [];
  if (strings.length === 0) return Buffer.from([0]);
  const parts: Buffer[] = [];
  for (const s of strings) {
    const b = Buffer.from(String(s), "utf8");
    if (b.length > 255) throw new RangeError("TXT string too long");
    parts.push(Buffer.from([b.length]), b);
  }
  return Buffer.concat(parts);
}

function readTxt(buf: Buffer, offset: number, len: number): string[] {
  const out: string[] = [];
  let pos = offset;
  const end = offset + len;
  while (pos < end) {
    const l = buf[pos++]!;
    if (l === 0 || pos + l > end) break;
    out.push(buf.toString("utf8", pos, pos + l));
    pos += l;
  }
  return out;
}

type DnsRR = {
  name: string;
  type: string | number;
  data?: string | string[] | Record<string, string> | Buffer;
  priority?: number;
  weight?: number;
  port?: number;
  target?: string;
  ttl?: number;
  cacheFlush?: boolean;
};

type DecodedRR = DnsRR & { class: number; cacheFlush: boolean };

function encodeRecord(rr: DnsRR): Buffer {
  const name = encodeName(rr.name);
  const typeNum = typeof rr.type === "number" ? rr.type : ((DNS_TYPE as Record<string, number>)[rr.type] ?? 0);
  let rdata: Buffer;
  if (typeNum === DNS_TYPE.PTR) {
    rdata = encodeName(String(rr.data));
  } else if (typeNum === DNS_TYPE.SRV) {
    const head = Buffer.allocUnsafe(6);
    head.writeUInt16BE(rr.priority ?? 0, 0);
    head.writeUInt16BE(rr.weight ?? 0, 2);
    head.writeUInt16BE(rr.port ?? 0, 4);
    rdata = Buffer.concat([head, encodeName(rr.target ?? "")]);
  } else if (typeNum === DNS_TYPE.TXT) {
    rdata = encodeTxt(rr.data as string[] | Record<string, string>);
  } else if (typeNum === DNS_TYPE.A) {
    rdata = Buffer.from(String(rr.data).split(".").map((n) => parseInt(n, 10) & 0xff));
  } else {
    rdata = Buffer.isBuffer(rr.data) ? rr.data : Buffer.alloc(0);
  }
  const head = Buffer.allocUnsafe(10);
  head.writeUInt16BE(typeNum, 0);
  head.writeUInt16BE(DNS_CLASS_IN | (rr.cacheFlush ? 0x8000 : 0), 2);
  head.writeUInt32BE(rr.ttl ?? 120, 4);
  head.writeUInt16BE(rdata.length, 8);
  return Buffer.concat([name, head, rdata]);
}

function readRecord(buf: Buffer, offset: number): { record: DecodedRR; offset: number } {
  const { name, offset: o1 } = readName(buf, offset);
  const type = buf.readUInt16BE(o1);
  const klass = buf.readUInt16BE(o1 + 2);
  const ttl = buf.readUInt32BE(o1 + 4);
  const rdlength = buf.readUInt16BE(o1 + 8);
  const rdStart = o1 + 10;
  const rec: DecodedRR = {
    name,
    type: TYPE_NAME[type] ?? type,
    class: klass & 0x7fff,
    cacheFlush: !!(klass & 0x8000),
    ttl,
  };
  if (type === DNS_TYPE.PTR) {
    rec.data = readName(buf, rdStart).name;
  } else if (type === DNS_TYPE.SRV) {
    rec.priority = buf.readUInt16BE(rdStart);
    rec.weight = buf.readUInt16BE(rdStart + 2);
    rec.port = buf.readUInt16BE(rdStart + 4);
    rec.target = readName(buf, rdStart + 6).name;
  } else if (type === DNS_TYPE.TXT) {
    rec.data = readTxt(buf, rdStart, rdlength);
  } else if (type === DNS_TYPE.A) {
    rec.data = [buf[rdStart]!, buf[rdStart + 1]!, buf[rdStart + 2]!, buf[rdStart + 3]!].join(".");
  } else {
    rec.data = buf.subarray(rdStart, rdStart + rdlength);
  }
  return { record: rec, offset: rdStart + rdlength };
}

type DnsMessage = {
  id?: number;
  flags?: number;
  questions?: { name: string; type: string | number; unicastResponse?: boolean }[];
  answers?: DnsRR[];
  authorities?: DnsRR[];
  additionals?: DnsRR[];
};

/** Encode a DNS message to a Buffer. */
export function encodeDnsMessage(msg: DnsMessage = {}): Buffer {
  const { id = 0, flags = 0, questions = [], answers = [], authorities = [], additionals = [] } = msg;
  const header = Buffer.allocUnsafe(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(flags, 2);
  header.writeUInt16BE(questions.length, 4);
  header.writeUInt16BE(answers.length, 6);
  header.writeUInt16BE(authorities.length, 8);
  header.writeUInt16BE(additionals.length, 10);
  const parts: Buffer[] = [header];
  for (const q of questions) {
    const qhead = Buffer.allocUnsafe(4);
    const typeNum = typeof q.type === "number" ? q.type : ((DNS_TYPE as Record<string, number>)[q.type] ?? DNS_TYPE.PTR);
    qhead.writeUInt16BE(typeNum, 0);
    qhead.writeUInt16BE(DNS_CLASS_IN | (q.unicastResponse ? 0x8000 : 0), 2);
    parts.push(encodeName(q.name), qhead);
  }
  for (const a of [...answers, ...authorities, ...additionals]) parts.push(encodeRecord(a));
  return Buffer.concat(parts);
}

/** Decode a DNS message from a Buffer. */
export function decodeDnsMessage(buf: Buffer): {
  id: number; flags: number; qr: boolean;
  questions: { name: string; type: string | number; unicastResponse: boolean }[];
  answers: DecodedRR[]; authorities: DecodedRR[]; additionals: DecodedRR[];
} {
  if (buf.length < 12) throw new RangeError("DNS message shorter than 12-byte header");
  const id = buf.readUInt16BE(0);
  const flags = buf.readUInt16BE(2);
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  const ns = buf.readUInt16BE(8);
  const ar = buf.readUInt16BE(10);
  let pos = 12;
  const questions: { name: string; type: string | number; unicastResponse: boolean }[] = [];
  for (let i = 0; i < qd; i++) {
    const { name, offset } = readName(buf, pos);
    const type = buf.readUInt16BE(offset);
    const klass = buf.readUInt16BE(offset + 2);
    questions.push({ name, type: TYPE_NAME[type] ?? type, unicastResponse: !!(klass & 0x8000) });
    pos = offset + 4;
  }
  const readN = (n: number): DecodedRR[] => {
    const out: DecodedRR[] = [];
    for (let i = 0; i < n; i++) {
      const { record, offset } = readRecord(buf, pos);
      out.push(record); pos = offset;
    }
    return out;
  };
  return { id, flags, qr: !!(flags & 0x8000), questions, answers: readN(an), authorities: readN(ns), additionals: readN(ar) };
}

// ── mDNS / DNS-SD peer discovery ──────────────────────────────────────────────

function serviceType(name?: string): string {
  let s = String(name ?? "_561._tcp.local").replace(/\.$/, "");
  if (!s.startsWith("_")) s = `_${s}`;
  if (!/_(tcp|udp)\b/.test(s)) s += "._tcp";
  if (!s.endsWith(".local")) s += ".local";
  return s;
}

export type PeerRecord = {
  id: Buffer;
  name: string;
  host: string | null;
  port: number | null;
  addresses: string[];
  txt: Record<string, string | true>;
};

export type PeerDiscoveryOptions = {
  port?: number;
  serviceName?: string;
  nodeId?: Buffer;
  identity?: string;
  instance?: string;
  txt?: Record<string, string>;
  host?: string;
  addresses?: string[];
  k?: number;
  ttl?: number;
  multicast?: boolean;
};

export type PeerDiscovery = {
  nodeId: Buffer;
  serviceName: string;
  instanceName: string;
  routingTable: RoutingTable;
  peers(): PeerRecord[];
  on(event: string, fn: (...args: unknown[]) => void): PeerDiscovery;
  off(event: string, fn: (...args: unknown[]) => void): PeerDiscovery;
  once(event: string, fn: (...args: unknown[]) => void): PeerDiscovery;
  announce(): boolean;
  browse(): boolean;
  findNode(target: Buffer, query: (c: KadContact, t: Buffer) => Promise<KadContact[]>, opts?: { alpha?: number; signal?: AbortSignal }): Promise<KadContact[]>;
  readonly bound: boolean;
  close(): void;
};

/**
 * peerDiscovery(opts) — start LAN peer discovery + a Kademlia routing table.
 *
 * Events: "peer" (new peer seen), "peer-down" (peer gone), "error" (socket failure).
 * The dgram socket is unref'd so it never prevents process exit.
 * If multicast fails, the object still works as an in-memory routing table.
 */
export function peerDiscovery(opts: PeerDiscoveryOptions = {}): PeerDiscovery {
  const {
    port = 0,
    serviceName,
    nodeId,
    identity,
    instance = `node-${crypto.randomBytes(3).toString("hex")}`,
    txt = {},
    host = `${instance}.local`,
    addresses = [],
    k = DEFAULT_K,
    ttl = 120,
    multicast = true,
  } = opts;

  const svc = serviceType(serviceName);
  const selfId = Buffer.isBuffer(nodeId) && nodeId.length === ID_BYTES
    ? nodeId
    : sha256(identity ?? `${instance}.${svc}`);
  const instanceName = `${instance}.${svc}`;

  const emitter = new EventEmitter();
  const routingTable = new RoutingTable(selfId, { k });
  const peers = new Map<string, PeerRecord>();

  let socket: dgram.Socket | null = null;
  let bound = false;
  let closed = false;

  const peerId = (name: string, txtPairs: string[]): Buffer => {
    const idPair = txtPairs.find((s) => /^id=/.test(s));
    if (idPair) {
      const hex = idPair.slice(3).trim();
      if (/^[0-9a-fA-F]{64}$/.test(hex)) return Buffer.from(hex, "hex");
    }
    return sha256(name);
  };

  function ingest(msg: { answers: DecodedRR[]; additionals: DecodedRR[] }): void {
    const answers = [...msg.answers, ...msg.additionals];
    const ptrs = answers.filter((r) => r.type === "PTR" && r.name === svc);
    for (const ptr of ptrs) {
      const name = String(ptr.data);
      if (name === instanceName) continue;
      if (ptr.ttl === 0) { markDown(name); continue; }
      const srv = answers.find((r) => r.type === "SRV" && r.name === name);
      const txtRec = answers.find((r) => r.type === "TXT" && r.name === name);
      const txtPairs = Array.isArray(txtRec?.data) ? (txtRec!.data as string[]) : [];
      const target = srv?.target;
      const aRecs = answers.filter((r) => r.type === "A" && (r.name === target || r.name === name));
      const id = peerId(name, txtPairs);
      const hex = id.toString("hex");
      if (hex === selfId.toString("hex")) continue;
      const peer: PeerRecord = {
        id,
        name,
        host: target ?? null,
        port: srv?.port ?? null,
        addresses: aRecs.map((r) => String(r.data)),
        txt: Object.fromEntries(txtPairs.map((s) => { const i = s.indexOf("="); return i === -1 ? [s, true as true] : [s.slice(0, i), s.slice(i + 1)]; })),
      };
      const fresh = !peers.has(hex);
      peers.set(hex, peer);
      try { routingTable.insert({ id, host: peer.host, port: peer.port, addresses: peer.addresses, name }); } catch { /* ignore */ }
      if (fresh) emitter.emit("peer", peer);
    }
  }

  function markDown(name: string): void {
    for (const [hex, p] of peers) {
      if (p.name === name) {
        peers.delete(hex);
        routingTable.remove(p.id);
        emitter.emit("peer-down", p);
      }
    }
  }

  function announcementRecords(recordTtl = ttl): DnsRR[] {
    const txtPairs = { id: selfId.toString("hex"), ...txt };
    const recs: DnsRR[] = [
      { name: svc, type: "PTR", data: instanceName, ttl: recordTtl },
      { name: instanceName, type: "SRV", priority: 0, weight: 0, port: port || 0, target: host, ttl: recordTtl, cacheFlush: true },
      { name: instanceName, type: "TXT", data: txtPairs, ttl: recordTtl, cacheFlush: true },
    ];
    for (const a of addresses) recs.push({ name: host, type: "A", data: a, ttl: recordTtl, cacheFlush: true });
    return recs;
  }

  function sendMessage(msg: DnsMessage): boolean {
    if (!socket || !bound) return false;
    const buf = encodeDnsMessage(msg);
    try { socket.send(buf, 0, buf.length, MDNS_PORT, MDNS_ADDR); return true; }
    catch (err) { emitter.emit("error", err); return false; }
  }

  function announce(): boolean {
    return sendMessage({ flags: 0x8400, answers: announcementRecords() });
  }

  function browse(): boolean {
    return sendMessage({ flags: 0, questions: [{ name: svc, type: "PTR" }] });
  }

  function setupSocket(): void {
    if (!multicast) return;
    let sock: dgram.Socket;
    try {
      sock = dgram.createSocket({ type: "udp4", reuseAddr: true });
    } catch (err) { emitter.emit("error", err); return; }
    socket = sock;
    sock.on("error", (err) => { emitter.emit("error", err); try { sock.close(); } catch { /* ignore */ } bound = false; });
    sock.on("message", (buf: Buffer) => {
      let msg: ReturnType<typeof decodeDnsMessage>;
      try { msg = decodeDnsMessage(buf); } catch { return; }
      if (!msg.qr && msg.questions.some((q) => q.type === "PTR" && q.name === svc)) announce();
      if (msg.qr || msg.answers.length) ingest(msg);
    });
    try {
      sock.bind(MDNS_PORT, () => {
        try {
          sock.addMembership(MDNS_ADDR);
          sock.setMulticastTTL(255);
          try { sock.setMulticastLoopback(true); } catch { /* optional */ }
          bound = true;
          if (typeof (sock as unknown as { unref(): void }).unref === "function") {
            (sock as unknown as { unref(): void }).unref();
          }
          announce();
          browse();
        } catch (err) { emitter.emit("error", err); bound = false; }
      });
    } catch (err) { emitter.emit("error", err); }
  }

  setupSocket();

  const api: PeerDiscovery = {
    nodeId: selfId,
    serviceName: svc,
    instanceName,
    routingTable,
    peers: () => [...peers.values()],
    on: (event, fn) => { emitter.on(event, fn); return api; },
    off: (event, fn) => { emitter.off(event, fn); return api; },
    once: (event, fn) => { emitter.once(event, fn); return api; },
    announce,
    browse,
    findNode: (target, query, findOpts = {}) =>
      findNode(target, { table: routingTable, query, k, ...findOpts }),
    get bound() { return bound; },
    close() {
      if (closed) return;
      closed = true;
      try { sendMessage({ flags: 0x8400, answers: announcementRecords(0) }); } catch { /* ignore */ }
      try { socket?.close(); } catch { /* ignore */ }
      socket = null;
      bound = false;
      emitter.removeAllListeners();
    },
  };
  return api;
}
