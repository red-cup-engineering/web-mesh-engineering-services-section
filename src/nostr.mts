// mesh/nostr.ts — Nostr relay (NIP-01) over WebSocket.
//
// Events are stored as Memes: {subject: eventId, predicate: "nostr", object: kind}.
// Subscriptions are tracked in a UtteranceLog and fanned out on publish.
//
// This implements the NIP-01 protocol message format only. Signature verification
// requires secp256k1 — provide a verify callback or use the no-op (dev mode).

import * as crypto from "node:crypto";
import { witness, UtteranceLog, recallWhere } from "@red-cup-engineering/http-server-core-service/internal/witness";
import type { WsSession } from "@red-cup-engineering/http-edge-service/ws";
import type { App } from "@red-cup-engineering/http-server-core-service/types";

// ── Nostr types (NIP-01) ──────────────────────────────────────────────────────

export type NostrEvent = {
  id: string;          // 32-byte hex SHA-256
  pubkey: string;      // 32-byte hex pubkey
  created_at: number;  // Unix timestamp
  kind: number;        // event kind
  tags: string[][];
  content: string;
  sig: string;         // 64-byte hex schnorr signature
};

export type NostrFilter = {
  ids?: string[];
  authors?: string[];
  kinds?: number[];
  since?: number;
  until?: number;
  limit?: number;
  [key: string]: unknown; // tag filters: "#e", "#p", etc.
};

export type NostrRelayMessage =
  | ["EVENT", string, NostrEvent]   // EVENT <subscriptionId> <event>
  | ["EOSE", string]                 // EOSE <subscriptionId>
  | ["NOTICE", string]               // NOTICE <message>
  | ["OK", string, boolean, string]; // OK <eventId> <ok> <message>

export type NostrClientMessage =
  | ["EVENT", NostrEvent]             // publish event
  | ["REQ", string, ...NostrFilter[]] // subscribe
  | ["CLOSE", string];                // unsubscribe

// ── Event ID verification ────────────────────────────────────────────────────

function eventId(event: Omit<NostrEvent, "id" | "sig">): string {
  const data = JSON.stringify([0, event.pubkey, event.created_at, event.kind, event.tags, event.content]);
  return crypto.createHash("sha256").update(data).digest("hex");
}

function filterMatches(event: NostrEvent, filter: NostrFilter): boolean {
  if (filter.ids && !filter.ids.some((id) => event.id.startsWith(id))) return false;
  if (filter.authors && !filter.authors.some((a) => event.pubkey.startsWith(a))) return false;
  if (filter.kinds && !filter.kinds.includes(event.kind)) return false;
  if (filter.since != null && event.created_at < filter.since) return false;
  if (filter.until != null && event.created_at > filter.until) return false;
  // Tag filters
  for (const [key, val] of Object.entries(filter)) {
    if (!key.startsWith("#") || !Array.isArray(val)) continue;
    const tag = key.slice(1);
    const hasTag = event.tags.some((t) => t[0] === tag && val.includes(t[1]!));
    if (!hasTag) return false;
  }
  return true;
}

// ── Relay ─────────────────────────────────────────────────────────────────────

export type NostrRelayOptions = {
  /** Verify event signature. Return true to accept. Default: always accept (dev mode). */
  verify?: (event: NostrEvent) => boolean | Promise<boolean>;
  /** Max events to store (default 10_000). */
  maxEvents?: number;
  /** Max filters per subscription (default 10). */
  maxFilters?: number;
  /** Persist events beyond in-memory (optional). */
  onEvent?: (event: NostrEvent) => void;
};

type Subscription = { id: string; filters: NostrFilter[] };

export class NostrRelay {
  private store = new UtteranceLog();
  private events: NostrEvent[] = [];
  private sessions = new Map<string, { session: WsSession; subscriptions: Map<string, Subscription> }>();
  private opts: Required<Omit<NostrRelayOptions, "onEvent">> & { onEvent?: (e: NostrEvent) => void };

  constructor(opts: NostrRelayOptions = {}) {
    this.opts = {
      verify: opts.verify ?? (() => true),
      maxEvents: opts.maxEvents ?? 10_000,
      maxFilters: opts.maxFilters ?? 10,
      ...(opts.onEvent !== undefined ? { onEvent: opts.onEvent } : {}),
    };
  }

  private send(session: WsSession, msg: NostrRelayMessage): void {
    try { session.send(JSON.stringify(msg)); } catch { /* ignore closed sessions */ }
  }

  private publish(event: NostrEvent): void {
    for (const { session, subscriptions } of this.sessions.values()) {
      for (const sub of subscriptions.values()) {
        if (sub.filters.some((f) => filterMatches(event, f))) {
          this.send(session, ["EVENT", sub.id, event]);
        }
      }
    }
  }

  /** Connect a WsSession to the relay. Returns cleanup function. */
  connect(session: WsSession): () => void {
    const sessionRecord = { session, subscriptions: new Map<string, Subscription>() };
    this.sessions.set(session.id, sessionRecord);

    session.on("message", (msg) => {
      if (msg.type !== "text") return;
      let parsed: NostrClientMessage;
      try { parsed = JSON.parse(msg.data) as NostrClientMessage; } catch { return; }

      if (parsed[0] === "EVENT") {
        void this.handleEvent(session, parsed[1] as NostrEvent);
      } else if (parsed[0] === "REQ") {
        const subId = parsed[1] as string;
        const filters = parsed.slice(2) as NostrFilter[];
        if (filters.length > this.opts.maxFilters) {
          this.send(session, ["NOTICE", "too many filters"]);
          return;
        }
        sessionRecord.subscriptions.set(subId, { id: subId, filters });
        // Send stored events that match
        for (const event of this.events) {
          if (filters.some((f) => filterMatches(event, f))) {
            this.send(session, ["EVENT", subId, event]);
          }
        }
        this.send(session, ["EOSE", subId]);
      } else if (parsed[0] === "CLOSE") {
        sessionRecord.subscriptions.delete(parsed[1] as string);
      }
    });

    session.on("close", () => this.sessions.delete(session.id));

    return () => this.sessions.delete(session.id);
  }

  private async handleEvent(session: WsSession, event: NostrEvent): Promise<void> {
    // Verify ID
    const expectedId = eventId(event);
    if (event.id !== expectedId) {
      this.send(session, ["OK", event.id, false, "invalid: bad event id"]);
      return;
    }

    // Check duplicate
    const existing = recallWhere(this.store, { subject: event.id, predicate: "nostr" });
    if (existing.length > 0) {
      this.send(session, ["OK", event.id, true, "duplicate"]);
      return;
    }

    // Verify signature
    const ok = await this.opts.verify(event);
    if (!ok) {
      this.send(session, ["OK", event.id, false, "invalid: bad signature"]);
      return;
    }

    witness(this.store, { subject: event.id, predicate: "nostr", object: String(event.kind) }, [true, false]);

    if (this.events.length >= this.opts.maxEvents) this.events.shift();
    this.events.push(event);
    this.opts.onEvent?.(event);
    this.publish(event);

    this.send(session, ["OK", event.id, true, ""]);
  }

  get eventCount(): number { return this.events.length; }
  get sessionCount(): number { return this.sessions.size; }
}

export function nostrRelay(opts: NostrRelayOptions = {}): NostrRelay {
  return new NostrRelay(opts);
}
