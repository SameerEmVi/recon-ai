"""
Live asset-graph assembly for the Map view.

Projects the persisted event stream into an **entity graph** — the clean "map of
the target" (domain → subdomain → ip → service → url / technology / finding /
email), deduped by identity — rather than a raw per-event dump. Edges come
straight from the data recon-ai already carries (`IpData.resolved_from` for
host→ip, the host field / URL host for everything else).

`graph_delta()` is the single source of truth for graph construction: it turns
ONE event into the nodes + edges it implies, and is used by BOTH this REST
assembler (initial load) and the live WebSocket stream (`api/ws.py`), so the map
and the live deltas can never drift. It is pure (no DB, no network) and
unit-tested directly.

Reads ONLY through the existing repositories; degrades gracefully with no DB.
"""

from __future__ import annotations

from urllib.parse import urlsplit
from uuid import UUID

_MAX_NODES = 2500          # render ceiling — a huge scan can't balloon the payload
_MAX_EVENTS = 6000         # events scanned to build the graph (oldest-first)

# Node kinds (the frontend styles/legends by these).
KINDS = ("domain", "host", "ip", "service", "port", "tech", "url", "finding",
         "anomaly", "email")


def _host_of(url: str) -> str | None:
    """Best-effort hostname from a URL; None if unparseable."""
    try:
        h = urlsplit(url).hostname
        return h or None
    except Exception:
        return None


def _short_url(url: str, cap: int = 60) -> str:
    """A compact label for a URL node: path (+query trimmed), host as fallback."""
    try:
        parts = urlsplit(url)
        label = parts.path or "/"
        if parts.query:
            label += "?…"
        if label in ("", "/"):
            label = parts.netloc or url
    except Exception:
        label = url
    return label[:cap]


def _node(nid: str, kind: str, label: str, **attrs) -> dict:
    n = {"id": nid, "kind": kind, "label": label}
    # drop None attrs so the payload stays lean
    n.update({k: v for k, v in attrs.items() if v is not None and v != ""})
    return n


def _edge(src: str, dst: str, rel: str) -> dict:
    return {"id": f"{src}->{dst}:{rel}", "source": src, "target": dst, "rel": rel}


def graph_delta(event_type: str, data: dict, root_domain: str | None = None
                ) -> tuple[list[dict], list[dict]]:
    """Turn one event into (nodes, edges). Pure. Emits every node an edge touches
    (nodes dedupe by id downstream), so endpoints always exist. Unknown or empty
    shapes yield ([], [])."""
    event_type = (event_type or "").lower()   # accept EventType.value ("SUBDOMAIN") or lower
    data = data or {}
    nodes: list[dict] = []
    edges: list[dict] = []

    def host_node(h: str) -> str:
        nid = f"host:{h}"
        nodes.append(_node(nid, "host", h))
        # Tie a discovered host back to the scan root (if it's a child of it).
        if root_domain and h != root_domain and h.endswith("." + root_domain):
            rid = f"domain:{root_domain}"
            nodes.append(_node(rid, "domain", root_domain))
            edges.append(_edge(rid, nid, "subdomain"))
        return nid

    if event_type == "subdomain":
        h = data.get("hostname", "")
        if h:
            host_node(h)

    elif event_type == "dns_record":
        h = data.get("hostname", "")
        rt = (data.get("record_type") or "").upper()
        val = data.get("value", "")
        if h and val:
            hid = host_node(h)
            if rt in ("A", "AAAA"):
                ip = f"ip:{val}"
                nodes.append(_node(ip, "ip", val))
                edges.append(_edge(hid, ip, "resolves"))
            elif rt == "CNAME":
                tid = host_node(val)
                edges.append(_edge(hid, tid, "cname"))
            elif rt in ("MX", "NS"):
                tid = host_node(val)
                edges.append(_edge(hid, tid, rt.lower()))

    elif event_type == "ip":
        addr = data.get("address", "")
        if addr:
            ip = f"ip:{addr}"
            nodes.append(_node(ip, "ip", addr))
            rf = data.get("resolved_from")
            if rf:
                hid = host_node(rf)
                edges.append(_edge(hid, ip, "resolves"))

    elif event_type == "open_port":
        h = data.get("host", "")
        port = data.get("port")
        if h and port:
            hid = host_node(h)
            proto = data.get("protocol", "tcp")
            pid = f"port:{h}:{port}"
            nodes.append(_node(pid, "port", f"{port}/{proto}", port=port))
            edges.append(_edge(hid, pid, "port"))

    elif event_type == "http_service":
        url = data.get("url", "")
        h = _host_of(url)
        if url and h:
            hid = host_node(h)
            sid = f"service:{url}"
            nodes.append(_node(sid, "service", h, url=url,
                               status=data.get("status_code"),
                               title=data.get("title"),
                               server=data.get("server")))
            edges.append(_edge(hid, sid, "service"))

    elif event_type == "technology":
        h = data.get("host", "")
        name = data.get("name", "")
        if h and name:
            hid = host_node(h)
            ver = data.get("version")
            tid = f"tech:{name}"
            nodes.append(_node(tid, "tech", f"{name} {ver}".strip() if ver else name,
                               version=ver, category=data.get("category")))
            edges.append(_edge(hid, tid, "runs"))

    elif event_type in ("url", "endpoint"):
        url = data.get("url", "")
        h = _host_of(url)
        if url and h:
            hid = host_node(h)
            uid = f"url:{url}"
            nodes.append(_node(uid, "url", _short_url(url), url=url,
                               method=data.get("method"),
                               status=data.get("status_code")))
            edges.append(_edge(hid, uid, "path"))

    elif event_type == "anomaly":
        h = data.get("host", "")
        cat = data.get("category") or "anomaly"
        if h:
            hid = host_node(h)
            aid = f"anomaly:{h}:{cat}:{(data.get('description') or '')[:40]}"
            nodes.append(_node(aid, "anomaly", cat, description=data.get("description")))
            edges.append(_edge(hid, aid, "observed"))

    elif event_type == "finding_candidate":
        h = data.get("host", "")
        title = data.get("title", "")
        cat = data.get("category", "")
        if h and title:
            hid = host_node(h)
            fid = f"finding:{h}:{title}:{cat}"
            nodes.append(_node(fid, "finding", title, category=cat,
                               severity=data.get("severity_hint")))
            edges.append(_edge(hid, fid, "finding"))

    elif event_type == "email":
        addr = data.get("address", "")
        if addr:
            eid = f"email:{addr}"
            nodes.append(_node(eid, "email", addr))
            anchor = _host_of(data.get("found_in") or "") or root_domain
            if anchor:
                hid = host_node(anchor)
                edges.append(_edge(hid, eid, "email"))

    return nodes, edges


def merge_delta(graph: dict, nodes: list[dict], edges: list[dict]) -> None:
    """Fold a delta into an accumulating {nodes: {id: node}, edges: {id: edge}}
    graph, in place. First node for an id wins id/kind/label; later deltas only
    fill in attributes that are still missing (a host first seen as a bare edge
    endpoint, later enriched by its own http_service event with status/title)."""
    for n in nodes:
        cur = graph["nodes"].get(n["id"])
        if cur is None:
            graph["nodes"][n["id"]] = dict(n)
        else:
            for k, v in n.items():
                cur.setdefault(k, v)
    for e in edges:
        graph["edges"].setdefault(e["id"], e)


async def build_graph(manager, db_url: str | None, scan_id: str | None = None) -> dict:
    out = {"scan": None, "nodes": [], "edges": [],
           "summary": {"nodes": 0, "edges": 0, "by_kind": {}}, "truncated": False}
    if not db_url:
        return out

    target = scan_id
    if not target:
        entries = manager.list()
        target = entries[0].scan_id if entries else None

    from database.repository import EventRepository, ScanRepository
    from database.session import make_engine, make_session_factory

    engine = make_engine(db_url)
    try:
        async with make_session_factory(engine)() as s:
            scan_repo = ScanRepository(s)
            scan = None
            if target:
                try:
                    scan = await scan_repo.get(UUID(target))
                except Exception:
                    scan = None
            if scan is None:
                recent = await scan_repo.recent_all(1)
                scan = recent[0] if recent else None
            if scan is None:
                return out

            out["scan"] = {"scan_id": str(scan.id), "domain": scan.target_domain,
                           "status": scan.status, "mode": scan.mode}

            records = await EventRepository(s).get_all(scan.id, _MAX_EVENTS)
            acc: dict = {"nodes": {}, "edges": {}}
            # Seed the root so a scan with results always shows its anchor.
            if scan.target_domain:
                acc["nodes"][f"domain:{scan.target_domain}"] = _node(
                    f"domain:{scan.target_domain}", "domain", scan.target_domain)
            for r in records:
                nodes, edges = graph_delta(r.type, r.data or {}, scan.target_domain)
                merge_delta(acc, nodes, edges)
                if len(acc["nodes"]) >= _MAX_NODES:
                    out["truncated"] = True
                    break

            node_list = list(acc["nodes"].values())
            node_ids = {n["id"] for n in node_list}
            # Keep only edges whose endpoints both survived the node cap.
            edge_list = [e for e in acc["edges"].values()
                         if e["source"] in node_ids and e["target"] in node_ids]
            by_kind: dict = {}
            for n in node_list:
                by_kind[n["kind"]] = by_kind.get(n["kind"], 0) + 1

            out["nodes"] = node_list
            out["edges"] = edge_list
            out["summary"] = {"nodes": len(node_list), "edges": len(edge_list),
                              "by_kind": by_kind}
    except Exception:
        # A read failure must never break the map — return what we have.
        pass
    finally:
        await engine.dispose()

    return out
