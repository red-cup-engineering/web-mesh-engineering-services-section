// mesh/antientropy.ts — Anti-entropy: full UtteranceLog synchronization between peers.
//
// Anti-entropy periodically picks a random peer and reconciles utterance sets:
//   1. Exchange digests (per-utterance hashes over the bedrock-dehydrated form).
//   2. Compute symmetric difference.
//   3. Transfer missing utterances in both directions.
//
// Contrary claims are transferred intact: opposed evidence at a cell stays
// two utterances in the replicated UtteranceLog, and the contradiction is
// held by whatever world a reader explicitly induces — never resolved during
// synchronization. The difference is per utterance identity (token mark
// value + claim mark value); identical utterances dedupe across peers. The
// wire format is bedrock-owned (dehydrateUtterances / rehydrateUtterances:
// {kind:"meme-topology.utteranceLog", utterances:[{token,claim}]}). Carriers
// never cross the wire; provenance never entered the log, so nothing else
// rides beside the utterance wire form.

import * as http from "node:http";
import * as https from "node:https";
import * as crypto from "node:crypto";
import {
  type UtteranceCarrier,
} from "@red-cup-engineering/relating";
import {
  dehydrateUtterances,
  rehydrateUtterances,
  type JsonValue,
} from "@red-cup-engineering/relating/codecs";
import { UtteranceLog } from "@red-cup-engineering/http-server-core-service/internal/witness";
import { PeerRegistry, type PeerAddress } from "./address.mjs";
import type { App } from "@red-cup-engineering/http-server-core-service/types";

export type AntiEntropyOptions = {
  self: PeerAddress;
  registry: PeerRegistry;
  store: UtteranceLog;
  intervalMs?: number;      // default 30_000 (30s)
  batchSize?: number;       // utterances per sync batch (default 256)
  onSync?: (peerId: string, added: number, received: number) => void;
};

type SyncRequest = { digest: string[] };
type SyncResponse = { missing: JsonValue | null; digest: string[] };

function hashUtterance(carrier: UtteranceCarrier): string {
  const dehydrated = dehydrateUtterances([carrier]);
  return crypto.createHash("sha256").update(JSON.stringify(dehydrated)).digest("hex").slice(0, 16);
}

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

export class AntiEntropyNode {
  private timer: ReturnType<typeof setInterval> | null = null;
  private opts: Required<AntiEntropyOptions>;

  constructor(opts: Required<AntiEntropyOptions>) { this.opts = opts; }

  start(): void {
    if (this.timer) return;
    this.timer = setInterval(() => void this.round(), this.opts.intervalMs);
    if (this.timer.unref) this.timer.unref();
  }

  stop(): void {
    if (this.timer) { clearInterval(this.timer); this.timer = null; }
  }

  private buildDigest(): string[] {
    return this.opts.store.utterances.map(hashUtterance);
  }

  private async round(): Promise<void> {
    const peers = this.opts.registry.all().filter((p) => p.id !== this.opts.self.id);
    if (!peers.length) return;
    const target = peers[Math.floor(Math.random() * peers.length)]!;

    const req: SyncRequest = { digest: this.buildDigest() };

    try {
      const res = await postJson(target.address, "/mesh/antientropy", req, 10_000) as SyncResponse | null;
      if (!res) return;

      // Utterances the peer has that we don't
      let received = 0;
      if (res.missing !== null && res.missing !== undefined) {
        const known = new Set(this.buildDigest());
        for (const carrier of rehydrateUtterances(res.missing)) {
          if (known.has(hashUtterance(carrier))) continue;
          this.opts.store.admit(carrier);
          received++;
        }
      }

      // Utterances we have that the peer didn't (derive from their digest)
      const peerHashes = new Set(res.digest ?? []);
      const toSend = this.opts.store.utterances.filter((carrier) => !peerHashes.has(hashUtterance(carrier)));
      this.opts.onSync(target.id, toSend.length, received);
    } catch { /* ignore — peer may be down */ }
  }

  /** Handle an incoming anti-entropy sync request. */
  handleSync(req: SyncRequest): SyncResponse {
    const peerHashes = new Set(req.digest);

    // Utterances the peer is missing (not in their digest)
    const missing = this.opts.store.utterances.filter((carrier) => !peerHashes.has(hashUtterance(carrier)));

    return {
      missing: missing.length ? dehydrateUtterances(missing.slice(0, this.opts.batchSize)) : null,
      digest: this.buildDigest(),
    };
  }
}

export function antiEntropyNode(opts: AntiEntropyOptions): AntiEntropyNode {
  return new AntiEntropyNode({
    intervalMs: opts.intervalMs ?? 30_000,
    batchSize: opts.batchSize ?? 256,
    onSync: opts.onSync ?? (() => {}),
    ...opts,
  });
}

/** Build anti-entropy endpoint resource to attach to an App. */
export function antiEntropyResource(node: AntiEntropyNode): NonNullable<App["resources"]>[number] {
  return {
    match: "/mesh/antientropy",
    methods: ["POST"],
    handler: async (ctx) => {
      const req = await import("@red-cup-engineering/http-server-core-service/http").then((m) => m.readJsonBody<SyncRequest>(ctx.req, { empty: { digest: [] } }));
      const res = node.handleSync(req);
      ctx.res.setHeader("Content-Type", "application/json");
      ctx.res.writeHead(200).end(JSON.stringify(res));
    },
  };
}
