// mesh/content.ts — Content-addressed store (CID via SHA-256).
//
// Each object is stored as a Meme: {subject: cid, predicate: "content", object: cid}.
// The CID is a hex-encoded SHA-256 digest (base16, no multicodec prefix — simple and dependency-free).
// Stored charge evidence determines whether content at a CID is locally available.

import * as crypto from "node:crypto";
import { cellValues, chargeOfUtterances, witness, UtteranceLog, recallWhere } from "@red-cup-engineering/http-server-core-service/internal/witness";
import type { App } from "@red-cup-engineering/http-server-core-service/types";

export type Cid = string; // hex SHA-256

export function cidOf(data: Buffer | Uint8Array): Cid {
  return crypto.createHash("sha256").update(data).digest("hex");
}

export class ContentStore {
  private store = new UtteranceLog();
  private objects = new Map<Cid, Buffer>();

  put(data: Buffer): Cid {
    const cid = cidOf(data);
    this.objects.set(cid, data);
    witness(this.store, { subject: cid, predicate: "content", object: cid }, [true, false]);
    return cid;
  }

  get(cid: Cid): Buffer | null {
    const memes = recallWhere(this.store, { subject: cid, predicate: "content" });
    if (!memes.length) return null;
    const g = chargeOfUtterances(memes);
    if (g !== "potential") return null;
    return this.objects.get(cid) ?? null;
  }

  has(cid: Cid): boolean {
    return this.get(cid) !== null;
  }

  delete(cid: Cid): void {
    this.objects.delete(cid);
    witness(this.store, { subject: cid, predicate: "content", object: cid }, [false, true]);
  }

  /** All known CIDs (including deleted — MPU settles availability). */
  cids(): Cid[] {
    const seen = new Set<string>();
    for (const carrier of this.store.utterances) seen.add(String(cellValues(carrier).subject));
    return [...seen];
  }

  /** CIDs available locally (MPU-settled to potential). */
  available(): Cid[] {
    return this.cids().filter((cid) => this.has(cid));
  }
}

export function contentStore(): ContentStore {
  return new ContentStore();
}

/** Build content-store REST endpoints. */
export function contentStoreResource(store: ContentStore, prefix = "/content"): NonNullable<App["resources"]>[number][] {
  return [
    {
      match: `${prefix}/:cid`,
      methods: ["GET", "HEAD"],
      handler: (ctx) => {
        const cid = ctx.params["cid"] ?? "";
        const data = store.get(cid);
        if (!data) { ctx.res.writeHead(404).end("Not Found"); return Promise.resolve(); }
        ctx.res.setHeader("Content-Type", "application/octet-stream");
        ctx.res.setHeader("Content-Length", data.length);
        ctx.res.setHeader("Cache-Control", "public, max-age=31536000, immutable");
        if (ctx.req.method === "HEAD") { ctx.res.writeHead(200).end(); return Promise.resolve(); }
        ctx.res.writeHead(200).end(data);
        return Promise.resolve();
      },
    },
    {
      match: prefix,
      methods: ["POST"],
      handler: async (ctx) => {
        const chunks: Buffer[] = [];
        await new Promise<void>((res, rej) => {
          ctx.req.on("data", (c: Buffer) => chunks.push(c));
          ctx.req.on("end", () => res());
          ctx.req.on("error", rej);
        });
        const data = Buffer.concat(chunks);
        const cid = store.put(data);
        ctx.res.setHeader("Content-Type", "application/json");
        ctx.res.writeHead(201).end(JSON.stringify({ cid }));
      },
    },
  ];
}
