// mesh/address.ts — Peer addressing and identity for the mesh layer.
//
// A Peer is a Meme: {subject: peerId, predicate: "peer", object: address}.
// Stored charge evidence settles peer reachability. Addresses are URIs (http/https/unix socket).

import { witness, chargeOfUtterances, recallWhere, UtteranceLog } from "@red-cup-engineering/http-server-core-service/internal/witness";

export type PeerId = string;

export type PeerAddress = {
  id: PeerId;
  address: string;        // "http://host:port" or "https://..." or "unix:///path/to.sock"
  tags?: string[];        // arbitrary grouping labels
  meta?: Record<string, string>;
};

export type PeerHealth = "up" | "down" | "unknown";

export class PeerRegistry {
  private store = new UtteranceLog();
  private peers = new Map<PeerId, PeerAddress>();

  register(peer: PeerAddress): void {
    this.peers.set(peer.id, peer);
    witness(this.store, { subject: peer.id, predicate: "peer", object: peer.address }, [true, false]);
    if (peer.tags) {
      for (const tag of peer.tags) {
        witness(this.store, { subject: peer.id, predicate: "tag", object: tag }, [true, false]);
      }
    }
  }

  deregister(id: PeerId): void {
    this.peers.delete(id);
    witness(this.store, { subject: id, predicate: "peer", object: "deregistered" }, [false, true]);
  }

  markHealth(id: PeerId, health: PeerHealth): void {
    const value: [boolean, boolean] = health === "up" ? [true, false] : health === "down" ? [false, true] : [true, true];
    witness(this.store, { subject: id, predicate: "health", object: health }, value);
  }

  settle(id: PeerId): "potential" | "active" | "stable" | "absurd" {
    return chargeOfUtterances(recallWhere(this.store, { subject: id, predicate: "peer" }));
  }

  get(id: PeerId): PeerAddress | undefined { return this.peers.get(id); }

  byTag(tag: string): PeerAddress[] {
    return [...this.peers.values()].filter((p) => p.tags?.includes(tag) && this.settle(p.id) === "potential");
  }

  all(): PeerAddress[] {
    return [...this.peers.values()].filter((p) => this.settle(p.id) === "potential");
  }
}

export function parsePeerAddress(raw: string): PeerAddress {
  const url = new URL(raw);
  const id = url.hostname + ":" + url.port;
  return { id, address: raw };
}
