"""Entity graph: link actors, organisations, wallets and IOCs through the alerts that mention them.

Wallet and IOC reuse is the strongest link, in the same spirit as Bitcoin co-spend clustering in
blockchain forensics: two personas sharing a payment address are probably one operator.
These links are heuristics, not proof (see README, Honest limitations).
"""
from __future__ import annotations

import networkx as nx

LINK_TYPES = ("btc", "eth", "xmr", "trx", "email", "domain", "ipv4", "sha256", "md5", "onion", "cve")


def build_graph(rows: list[dict]) -> nx.Graph:
    """rows: [{id, actor, org, category, score, iocs: {type: [values]}}]"""
    g = nx.Graph()
    for r in rows:
        item = f"item:{r['id']}"
        g.add_node(item, kind="item", label=(r.get("title") or r["id"])[:40], category=r.get("category"), score=r.get("score", 0))
        for key, kind in (("actor", "actor"), ("org", "org")):
            if r.get(key):
                n = f"{kind}:{r[key]}"
                g.add_node(n, kind=kind, label=r[key])
                g.add_edge(item, n, rel=kind)
        for typ, vals in (r.get("iocs") or {}).items():
            if typ not in LINK_TYPES:
                continue
            for v in vals:
                n = f"{typ}:{v}"
                g.add_node(n, kind=typ, label=v[:34] + ("..." if len(v) > 34 else ""))
                g.add_edge(item, n, rel=typ)
    return g


def linked_actors(g: nx.Graph) -> list[dict]:
    """Actors that share at least one wallet/IOC node, a hint of one operator behind several names."""
    out = []
    for n, d in g.nodes(data=True):
        if d.get("kind") in ("btc", "eth", "xmr", "trx", "email", "ipv4", "sha256", "md5"):
            actors = sorted({a for it in g.neighbors(n) for a in g.neighbors(it) if g.nodes[a].get("kind") == "actor"})
            if len(actors) >= 2:
                out.append({"shared": n, "type": d["kind"], "actors": actors})
    return out


def to_json(g: nx.Graph) -> dict:
    nodes = [{"id": n, **d} for n, d in g.nodes(data=True)]
    links = [{"source": a, "target": b, **d} for a, b, d in g.edges(data=True)]
    return {"nodes": nodes, "links": links}


def campaigns(g: nx.Graph) -> list[dict]:
    """Group alerts that are connected through shared indicators (wallets, IPs, hashes, emails).

    Actor and organisation nodes are ignored on purpose: two posts by the same handle are not a campaign,
    but two handles sharing a wallet is. Risk spreads with Personalized PageRank seeded on high-scoring items.
    """
    h = nx.Graph()
    for a, b, d in g.edges(data=True):
        if d.get("rel") in LINK_TYPES:
            h.add_edge(a, b)
    items = [n for n in g.nodes if g.nodes[n].get("kind") == "item"]
    seed = {n: g.nodes[n].get("score", 0) + 1 for n in items if n in h}
    ppr = nx.pagerank(h, personalization=seed) if seed else {}
    top = max(ppr.values(), default=1) or 1
    out = []
    for comp in nx.connected_components(h):
        its = sorted(n for n in comp if g.nodes[n].get("kind") == "item")
        if len(its) < 2:
            continue
        out.append({
            "items": [n.split(":", 1)[1] for n in its],
            "size": len(its),
            "max_score": max(g.nodes[n].get("score", 0) for n in its),
            "shared": sorted(g.nodes[n]["label"] for n in comp if g.nodes[n].get("kind") != "item")[:6],
            "risk": round(100 * max(ppr.get(n, 0) for n in its) / top),
        })
    return sorted(out, key=lambda c: (-c["max_score"], -c["size"]))
