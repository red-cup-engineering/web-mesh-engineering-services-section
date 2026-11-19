// mesh/gossip.ts — SWIM-inspired gossip protocol for peer discovery and health.
//
// Each gossip round:
//   1. Pick a random peer from the registry.
//   2. Send a /mesh/ping; if no ack within ackTimeout, indirect-ping via k random peers.
//   3. Store outcome as a Meme; stored charge evidence settles peer health.
//   4. Broadcast membership deltas (join/leave/suspect) to fanout peers.
//
// Messages are JSON objects over HTTP POST (no separate UDP socket required).

import * as http from "node:http";
import * as https from "node:https";
import { chargeOfUtterances, witness, UtteranceLog, recallCell } from "@red-cup-engineering/http-server-core-service/internal/witness";
import { PeerRegistry, type PeerId, type PeerAddress } from "./address.mjs";
import type { App } from "@red-cup-engineering/http-server-core-service/types";

export type GossipOptions = {
  self: PeerAddress;
  registry: PeerRegistry;
  intervalMs?: number;        // gossip round interval (default 1000)
  ackTimeoutMs?: number;      // direct ping timeout (default 500)
  indirectK?: number;         // peers to ask for indirect ping (default 3)
  fanout?: number;            // peers to broadcast to per round (default 3)
  onJoin?: (peer: PeerAddress) => void;
  onLeave?: (peer: PeerId) => void;
  onSuspect?: (peer: PeerId) => void;
};

export type GossipMessage = {
  type: "ping" | "ack" | "ping-req" | "broadcast";
  from: PeerId;
  target?: PeerId;
  members?: Array<{ id: PeerId; address: string; status: "alive" | "suspect" | "dead" }>;
};

async function postJson(address: string, path: string, body: unknown, timeoutMs: number): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const url = new URL(path, address);
    const data = Buffer.from(JSON.stringify(body), "utf8");
    const mod = url.protocol === "https:" ? https : http;
    const req = mod.request({
      hostname: url.hostname,
      port: url.port ? parseInt(url.port) : (url.protocol === "https:" ? 443 : 80),
      path: url.pathname,
      method: "POST",
      headers: { "Content-Type": "application/json", "Content-Length": data.length },
    }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (c: Buffer) => chunks.push(c));
      res.on("end", () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))); }
        catch { resolve(null); }
      });
    });
    req.setTimeout(timeoutMs, () => req.destroy());
    req.on("error", reject);
    req.write(data);
    req.end();
  });
}

function shuffle<T>(arr: T[]): T[] {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j]!, arr[i]!];
  }
  return arr;
}

export class GossipNode {
  private store = new UtteranceLog();
  private timer: ReturnType<typeof setInterval> | null = null;
  private suspects = new Set<PeerId>();
  private opts: Required<GossipOptions>;

  constructor(opts: Required<GossipOptions>) { this.opts = opts; }

  start(): void {
    if (this.timer) return;
    // Register self
    this.opts.registry.register(this.opts.self);
    this.timer = setInterval(() => void this.round(), this.opts.intervalMs);
    if (this.timer.unref) this.timer.unref();
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
    this.opts.registry.deregister(this.opts.self.id);
  }

  private async round(): Promise<void> {
    const peers = shuffle(this.opts.registry.all().filter((p) => p.id !== this.opts.self.id));
    if (!peers.length) return;

    const target = peers[0]!;
    const reachable = await this.directPing(target);

    if (!reachable) {
      // Indirect ping via k random peers
      const helpers = peers.slice(1, this.opts.indirectK + 1);
      const acks = await Promise.all(helpers.map((h) => this.indirectPing(h, target)));
      const anyAck = acks.some(Boolean);

      if (!anyAck) {
        this.markSuspect(target.id);
      }
    } else {
      this.clearSuspect(target.id);
    }

    // Broadcast membership delta
    const fanoutPeers = shuffle(peers).slice(0, this.opts.fanout);
    const members = this.opts.registry.all().map((p) => ({
      id: p.id,
      address: p.address,
      status: (this.suspects.has(p.id) ? "suspect" : "alive") as "alive" | "suspect",
    }));
    const msg: GossipMessage = { type: "broadcast", from: this.opts.self.id, members };
    await Promise.allSettled(fanoutPeers.map((p) => postJson(p.address, "/mesh/gossip", msg, this.opts.ackTimeoutMs)));
  }

  private async directPing(target: PeerAddress): Promise<boolean> {
    try {
      await postJson(target.address, "/mesh/ping", { type: "ping", from: this.opts.self.id }, this.opts.ackTimeoutMs);
      witness(this.store, { subject: target.id, predicate: "ping", object: "ack" }, [true, false]);
      return true;
    } catch {
      witness(this.store, { subject: target.id, predicate: "ping", object: "ack" }, [false, true]);
      return false;
    }
  }

  private async indirectPing(helper: PeerAddress, target: PeerAddress): Promise<boolean> {
    try {
      const res = await postJson(helper.address, "/mesh/ping-req", { type: "ping-req", from: this.opts.self.id, target: target.id }, this.opts.ackTimeoutMs * 2) as { ack?: boolean } | null;
      return res?.ack === true;
    } catch { return false; }
  }

  private markSuspect(id: PeerId): void {
    if (!this.suspects.has(id)) {
      this.suspects.add(id);
      this.opts.registry.markHealth(id, "down");
      this.opts.onSuspect(id);
    }
  }

  private clearSuspect(id: PeerId): void {
    if (this.suspects.has(id)) {
      this.suspects.delete(id);
      this.opts.registry.markHealth(id, "up");
    }
  }

  /** Handle an incoming gossip message (from the /mesh/gossip endpoint). */
  handleBroadcast(msg: GossipMessage): void {
    if (msg.type !== "broadcast" || !msg.members) return;
    for (const m of msg.members) {
      if (m.id === this.opts.self.id) continue;
      if (m.status === "dead") {
        this.opts.registry.deregister(m.id);
        this.opts.onLeave(m.id);
      } else {
        const existing = this.opts.registry.get(m.id);
        if (!existing) {
          this.opts.registry.register({ id: m.id, address: m.address });
          this.opts.onJoin({ id: m.id, address: m.address });
        }
        if (m.status === "suspect") this.markSuspect(m.id);
        else this.clearSuspect(m.id);
      }
    }
  }

  /** Settle peer health from stored charge evidence. */
  settle(id: PeerId): "potential" | "active" | "stable" | "absurd" {
    const pings = recallCell(this.store, { subject: id, predicate: "ping", object: "ack" });
    if (!pings.length) return "absurd";
    return chargeOfUtterances(pings);
  }
}

export function gossipNode(opts: GossipOptions): GossipNode {
  return new GossipNode({
    intervalMs: opts.intervalMs ?? 1000,
    ackTimeoutMs: opts.ackTimeoutMs ?? 500,
    indirectK: opts.indirectK ?? 3,
    fanout: opts.fanout ?? 3,
    onJoin: opts.onJoin ?? (() => {}),
    onLeave: opts.onLeave ?? (() => {}),
    onSuspect: opts.onSuspect ?? (() => {}),
    ...opts,
  });
}

/** Build mesh endpoint resources to attach to an App. */
export function meshResources(node: GossipNode, registry: PeerRegistry): App["resources"] {
  return [
    {
      match: "/mesh/ping",
      methods: ["POST"],
      handler: async (ctx) => {
        ctx.res.setHeader("Content-Type", "application/json");
        ctx.res.writeHead(200).end(JSON.stringify({ ack: true }));
      },
    },
    {
      match: "/mesh/ping-req",
      methods: ["POST"],
      handler: async (ctx) => {
        const msg = await import("@red-cup-engineering/http-server-core-service/http").then((m) => m.readJsonBody<GossipMessage>(ctx.req, { empty: { type: "ping-req", from: "" } }));
        const target = registry.get(msg.target ?? "");
        let ack = false;
        if (target) {
          try {
            await postJson(target.address, "/mesh/ping", { type: "ping", from: "relay" }, 500);
            ack = true;
          } catch { /* */ }
        }
        ctx.res.setHeader("Content-Type", "application/json");
        ctx.res.writeHead(200).end(JSON.stringify({ ack }));
      },
    },
    {
      match: "/mesh/gossip",
      methods: ["POST"],
      handler: async (ctx) => {
        const msg = await import("@red-cup-engineering/http-server-core-service/http").then((m) => m.readJsonBody<GossipMessage>(ctx.req, { empty: { type: "broadcast", from: "" } }));
        node.handleBroadcast(msg);
        ctx.res.writeHead(204).end();
      },
    },
    {
      match: "/mesh/members",
      methods: ["GET"],
      handler: (ctx) => {
        ctx.res.setHeader("Content-Type", "application/json");
        ctx.res.writeHead(200).end(JSON.stringify(registry.all()));
        return Promise.resolve();
      },
    },
  ];
}
