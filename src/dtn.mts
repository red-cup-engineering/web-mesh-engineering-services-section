// mesh/dtn.ts — Delay-Tolerant Networking (DTN) bundle layer.
//
// Implements a minimal RFC 5050-inspired bundle protocol for store-and-forward
// communication across intermittently connected nodes. Bundles are stored as Memes;
// stored charge evidence determines whether a bundle is still in flight.
// Contradicted delivery (stable) means the bundle was acknowledged by multiple routes simultaneously.

import * as crypto from "node:crypto";
import { chargeOfUtterances, witness, UtteranceLog, recallWhere } from "@red-cup-engineering/http-server-core-service/internal/witness";
import type { App } from "@red-cup-engineering/http-server-core-service/types";

export type BundleId = string;

export type Bundle = {
  id: BundleId;
  source: string;
  destination: string;
  createdAt: number;
  expiresAt: number;
  payload: Buffer;
  custodian?: string;
  hopCount: number;
  maxHops: number;
};

export type DtnOptions = {
  nodeId: string;
  maxHops?: number;         // default 8
  bundleTtlMs?: number;     // default 24 hours
  onDeliver?: (bundle: Bundle) => void | Promise<void>;
  onExpire?: (bundle: Bundle) => void;
};

export function bundleId(): BundleId {
  return crypto.randomBytes(16).toString("hex");
}

export function encodeBundle(bundle: Bundle): Buffer {
  const meta = JSON.stringify({
    id: bundle.id,
    source: bundle.source,
    destination: bundle.destination,
    createdAt: bundle.createdAt,
    expiresAt: bundle.expiresAt,
    custodian: bundle.custodian,
    hopCount: bundle.hopCount,
    maxHops: bundle.maxHops,
  });
  const metaBuf = Buffer.from(meta, "utf8");
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(metaBuf.length, 0);
  return Buffer.concat([header, metaBuf, bundle.payload]);
}

export function decodeBundle(data: Buffer): Bundle | null {
  if (data.length < 4) return null;
  const metaLen = data.readUInt32BE(0);
  if (data.length < 4 + metaLen) return null;
  try {
    const meta = JSON.parse(data.slice(4, 4 + metaLen).toString("utf8")) as Omit<Bundle, "payload">;
    const payload = data.slice(4 + metaLen);
    return { ...meta, payload };
  } catch { return null; }
}

export class DtnNode {
  private store = new UtteranceLog();
  private bundles = new Map<BundleId, Bundle>();
  private delivered = new Set<BundleId>();
  private opts: Required<DtnOptions>;

  constructor(opts: DtnOptions) {
    this.opts = {
      maxHops: opts.maxHops ?? 8,
      bundleTtlMs: opts.bundleTtlMs ?? 86_400_000,
      onDeliver: opts.onDeliver ?? (() => {}),
      onExpire: opts.onExpire ?? (() => {}),
      ...opts,
    };
  }

  /** Create and store a bundle for forwarding. */
  send(destination: string, payload: Buffer): Bundle {
    const now = Date.now(); // law-allow: wall-clock-as-data — bundle createdAt/expiresAt are DTN TTL testimony, not ordering
    const bundle: Bundle = {
      id: bundleId(),
      source: this.opts.nodeId,
      destination,
      createdAt: now,
      expiresAt: now + this.opts.bundleTtlMs,
      payload,
      custodian: this.opts.nodeId,
      hopCount: 0,
      maxHops: this.opts.maxHops,
    };
    this.storeBundle(bundle);
    return bundle;
  }

  private storeBundle(bundle: Bundle): void {
    this.bundles.set(bundle.id, bundle);
    witness(this.store, { subject: bundle.id, predicate: "bundle", object: "in-flight" }, [true, false]);
  }

  /** Receive a bundle (from a peer or relay). Returns true if accepted. */
  async receive(bundle: Bundle): Promise<boolean> {
    if (this.delivered.has(bundle.id)) return false;
    if (Date.now() > bundle.expiresAt) { this.opts.onExpire(bundle); return false; } // law-allow: wall-clock-as-data — bundle TTL bookkeeping (DTN expiry), not event ordering
    if (bundle.hopCount >= bundle.maxHops) return false;

    const existing = recallWhere(this.store, { subject: bundle.id, predicate: "bundle" });
    const g = chargeOfUtterances(existing);
    if (g === "active") return false; // already delivered

    if (bundle.destination === this.opts.nodeId) {
      // Deliver locally
      this.delivered.add(bundle.id);
      witness(this.store, { subject: bundle.id, predicate: "bundle", object: "delivered" }, [false, true]);
      await this.opts.onDeliver(bundle);
      return true;
    }

    // Store for forwarding
    const forwarded = { ...bundle, hopCount: bundle.hopCount + 1, custodian: this.opts.nodeId };
    this.storeBundle(forwarded);
    return true;
  }

  /** Get bundles to forward to a connected peer (all in-flight, not expired). */
  bundlesFor(_peerId: string): Bundle[] {
    const now = Date.now(); // law-allow: wall-clock-as-data — bundle TTL bookkeeping (DTN expiry), not event ordering
    return [...this.bundles.values()].filter((b) =>
      !this.delivered.has(b.id) &&
      b.expiresAt > now &&
      b.hopCount < b.maxHops,
    );
  }

  /** Acknowledge delivery of a bundle (removes from forward queue). */
  ack(bundleId: BundleId): void {
    this.bundles.delete(bundleId);
    this.delivered.add(bundleId);
    witness(this.store, { subject: bundleId, predicate: "bundle", object: "acked" }, [false, true]);
  }

  /** Purge expired bundles. */
  purgeExpired(): number {
    const now = Date.now(); // law-allow: wall-clock-as-data — bundle TTL bookkeeping (DTN expiry), not event ordering
    let count = 0;
    for (const [id, bundle] of this.bundles) {
      if (bundle.expiresAt <= now) {
        this.bundles.delete(id);
        this.opts.onExpire(bundle);
        count++;
      }
    }
    return count;
  }
}

export function dtnNode(opts: DtnOptions): DtnNode {
  return new DtnNode(opts);
}

/** Build DTN relay endpoints. */
export function dtnResource(node: DtnNode): NonNullable<App["resources"]>[number][] {
  return [
    {
      match: "/dtn/bundles",
      methods: ["POST"],
      handler: async (ctx) => {
        const chunks: Buffer[] = [];
        await new Promise<void>((res, rej) => {
          ctx.req.on("data", (c: Buffer) => chunks.push(c));
          ctx.req.on("end", () => res());
          ctx.req.on("error", rej);
        });
        const data = Buffer.concat(chunks);
        const bundle = decodeBundle(data);
        if (!bundle) { ctx.res.writeHead(400).end("Invalid bundle"); return; }
        const accepted = await node.receive(bundle);
        ctx.res.writeHead(accepted ? 202 : 409).end();
      },
    },
    {
      match: "/dtn/bundles",
      methods: ["GET"],
      handler: (ctx) => {
        const peerId = ctx.url.searchParams.get("peer") ?? "";
        const bundles = node.bundlesFor(peerId).map((b) => encodeBundle(b).toString("base64"));
        ctx.res.setHeader("Content-Type", "application/json");
        ctx.res.writeHead(200).end(JSON.stringify({ bundles }));
        return Promise.resolve();
      },
    },
  ];
}
