#!/usr/bin/env python3
"""
agentic_race_hunter.py -- let an agent HYPOTHESIZE kernel race conditions from the
Orion graph, then CHECK each hypothesis against the graph, and emit the survivors
as RaceFuzz targets.

This goes beyond gen_terrain_pairs.py (which mechanically enumerates every
teardown x use op-pair). Here the graph provides *evidence*, and a Claude agent
reasons over it the way Orion's discovery agents do: it proposes a SPECIFIC race
(this free site, that concurrent reader, this shared object, this window), maps it
to the harness's syscall-level op vocabulary, cites the graph facts it relied on,
and rates confidence. A separate verify pass re-queries the graph to confirm those
cited facts before any hypothesis becomes a fuzzer target -- a claim is never
trusted until a read-only query backs it (Orion's grounding discipline).

Pipeline (each stage is a subcommand so the slow graph work runs once):

  extract     read-only graph queries -> evidence bundles (needs Neo4j)
  hypothesize feed bundles to `claude -p` -> race hypotheses (needs claude CLI)
  verify      re-check each hypothesis's cited facts vs the graph (needs Neo4j)
  emit        write CONFIRMED hypotheses as harness test cases + a report
  run         extract -> hypothesize -> verify -> emit, in one go

Because the Neo4j container does not survive between WSL sessions, run the
graph-touching stages inside one WSL invocation (see run_agentic_hunt.sh).

Usage:
  python3 agentic_race_hunter.py extract     --scan-id kernel-full --out bundles.json
  python3 agentic_race_hunter.py hypothesize --bundles bundles.json --out hypos.json
  python3 agentic_race_hunter.py verify      --scan-id kernel-full --hypos hypos.json --out verified.json
  python3 agentic_race_hunter.py emit        --verified verified.json --corpus ~/corpus-agentic
"""
import argparse
import json
import os
import subprocess
import sys
import time

from neo4j import GraphDatabase
from neo4j.exceptions import ServiceUnavailable

URI = "bolt://localhost:7688"
AUTH = ("neo4j", "orion_dev_changeme")

FREE_PATTERNS = ["kfree", "kvfree", "kfree_rcu", "call_rcu", "free_percpu", "bpf_map_put",
                 "bpf_map_free", "bpf_prog_put", "module_put", "put_net",
                 "nft_deactivate", "nft_destroy", "nft_set_destroy", "nft_chain_destroy",
                 "nf_tables_chain_destroy", "qdisc_put", "qdisc_destroy", "tcf_destroy",
                 "tcf_block_put", "tcf_chain_put", "tcf_proto_destroy", "kmem_cache_free"]
READ_PATTERNS = ["_lookup_elem", "lookup", "rhashtable_lookup", "rcu_dereference",
                 "list_for_each", "copy_to_user"]
GUARD_PATTERNS = ["spin_lock", "mutex_lock", "rcu_read_lock", "write_lock", "read_lock",
                  "down_write", "down_read", "local_bh_disable", "preempt_disable",
                  "raw_spin_lock"]
RCU_FREE = {"call_rcu", "kfree_rcu", "call_rcu_tasks", "call_rcu_tasks_trace"}

SUBSYS = {"kernel/bpf": "bpf", "net/netfilter": "nft", "net/sched": "sched"}

# Harness op vocabulary given to the agent so it maps a race to something the
# fuzzer can actually drive (must match vm/harness/main.c).
HARNESS_OPS = {
    "bpf":   {"free": ["close_map", "close_prog", "map_delete_elem"],
              "use":  ["map_lookup_elem", "map_update_elem", "map_freeze", "prog_load"],
              "map_types": {"hash": 1, "array": 2, "percpu_hash": 5, "lru_hash": 9}},
    "nft":   {"free": ["nft_del_table", "nft_del_chain", "nft_del_set_elem", "nft_flush"],
              "use":  ["nft_add_rule", "send_udp_packet"]},
    "sched": {"free": ["del_qdisc", "del_class", "del_filter"],
              "use":  ["add_qdisc", "add_class", "send_udp_packet"]},
}


def _wait(driver, tries=45, delay=2):
    for _ in range(tries):
        try:
            with driver.session() as s:
                s.run("RETURN 1").single()
            return True
        except (ServiceUnavailable, OSError):
            time.sleep(delay)
    return False


def subsystem_of(path):
    for k, v in SUBSYS.items():
        if k in (path or ""):
            return v
    return None


# ---------------- extract ----------------

def cmd_extract(args):
    d = GraphDatabase.driver(URI, auth=AUTH)
    if not _wait(d):
        print("neo4j not reachable on 7688", file=sys.stderr)
        return 1
    sid = args.scan_id
    free_or = " OR ".join(f"cc.name CONTAINS '{p}'" for p in FREE_PATTERNS)
    guard_or = " OR ".join(f"g.name CONTAINS '{p}'" for p in GUARD_PATTERNS)
    read_or = " OR ".join(f"cc.name CONTAINS '{p}'" for p in READ_PATTERNS)

    with d.session() as s:
        n = s.run("MATCH (n {scan_id:$sid}) RETURN count(n) AS c", sid=sid).single()["c"]
        if n == 0:
            print(f"no data for scan_id={sid}", file=sys.stderr)
            return 1
        print(f"extract: {sid} ({n} nodes)", file=sys.stderr)

        # 1) union set of methods reachable from any seeded syscall entry (dispatch-aware).
        print("  computing syscall-reachable method set...", file=sys.stderr)
        reach_q = (
            "MATCH (e:EntryPoint {scan_id:$sid})-[:ENTERS_AT]->(em:CpgMethod {scan_id:$sid}) "
            "MATCH (em)-[:CONTAINS_CALL|RESOLVES_TO*1..6]->"
            "(:CpgCall {scan_id:$sid})-[:RESOLVES_TO]->(m:CpgMethod {scan_id:$sid}) "
            "RETURN DISTINCT m.full_name AS fn"
        )
        reachable = {r["fn"] for r in s.run(reach_q, sid=sid)}
        print(f"  {len(reachable)} methods reachable from syscall entries", file=sys.stderr)

        # 2) same-file readers (candidate racing "use" side), grouped by file.
        readers_by_file = {}
        rq = (
            f"MATCH (m:CpgMethod {{scan_id:$sid}})-[:CONTAINS_CALL]->(cc:CpgCall {{scan_id:$sid}}) "
            f"WHERE ({read_or}) AND NOT m.is_external AND NOT m.full_name CONTAINS '<' "
            "RETURN m.file_path AS file, collect(DISTINCT m.full_name) AS readers"
        )
        for r in s.run(rq, sid=sid):
            readers_by_file[r["file"]] = r["readers"]

        # 3) unguarded free/mutate sites = the candidate teardown ends.
        cq = (
            f"MATCH (m:CpgMethod {{scan_id:$sid}})-[:CONTAINS_CALL]->(cc:CpgCall {{scan_id:$sid}}) "
            f"WHERE ({free_or}) AND NOT m.is_external AND NOT m.full_name CONTAINS '<' "
            "WITH m, collect(DISTINCT cc.name) AS free_ops "
            f"OPTIONAL MATCH (m)-[:CONTAINS_CALL]->(g:CpgCall {{scan_id:$sid}}) WHERE ({guard_or}) "
            "WITH m, free_ops, collect(DISTINCT g.name) AS guards "
            "WHERE size(guards)=0 "
            "RETURN m.full_name AS site, m.file_path AS file, free_ops "
            "ORDER BY site LIMIT $limit"
        )
        bundles = []
        for r in s.run(cq, sid=sid, limit=args.limit):
            sub = subsystem_of(r["file"])
            if not sub:
                continue
            free_ops = r["free_ops"]
            free_kind = "rcu_deferred" if any(o in RCU_FREE for o in free_ops) else "immediate"
            sibs = [x for x in readers_by_file.get(r["file"], []) if x != r["site"]][:6]
            bundles.append({
                "site": r["site"],
                "file": r["file"],
                "subsystem": sub,
                "free_ops": free_ops,
                "free_kind": free_kind,
                "unguarded": True,
                "reachable_from_syscall": r["site"] in reachable,
                "sibling_readers": sibs,
            })
    d.close()

    # keep reachable, prefer rcu_deferred (wider window), cap.
    bundles.sort(key=lambda b: (not b["reachable_from_syscall"],
                                b["free_kind"] != "rcu_deferred", b["site"]))
    bundles = bundles[:args.max_bundles]
    with open(args.out, "w") as f:
        json.dump({"scan_id": sid, "harness_ops": HARNESS_OPS, "bundles": bundles}, f, indent=2)
    reach_n = sum(1 for b in bundles if b["reachable_from_syscall"])
    print(f"wrote {len(bundles)} evidence bundles to {args.out} "
          f"({reach_n} syscall-reachable)", file=sys.stderr)
    return 0


# ---------------- hypothesize (the agent) ----------------

AGENT_SYSTEM = (
    "You are a Linux-kernel race-condition analyst working for a targeted concurrency "
    "fuzzer (RaceFuzz). You are given EVIDENCE extracted from a code-property graph of "
    "real kernel source (bpf/nft/sched): methods that free or mutate a shared object with "
    "no lock/RCU guard visible in their body, whether each is reachable from a syscall "
    "entry, the free kind (immediate vs RCU-deferred), and sibling functions that read the "
    "same object. Your job: propose CONCRETE race hypotheses and map each to the fuzzer's "
    "syscall-level op vocabulary so it can be driven.\n\n"
    "Rules:\n"
    "- Only use facts present in the evidence. Do NOT invent functions, files, or reach "
    "that the evidence does not state. If a site is not reachable_from_syscall, say so and "
    "lower confidence.\n"
    "- A race needs a teardown/free side AND a concurrent use side on the SAME object, "
    "reachable from user space. RCU-deferred frees have a wider, more raceable window.\n"
    "- Map each side to one op from harness_ops[subsystem] (free-op for the teardown, "
    "use-op for the reader). Pick a bpf map_type when relevant.\n"
    "- Output ONLY a JSON object: {\"hypotheses\":[...]}. Each hypothesis:\n"
    "  {\"id\": short_slug, \"subsystem\": ..., \"shared_object\": ...,\n"
    "   \"free_site\": <site from evidence>, \"free_op\": <harness free op>,\n"
    "   \"use_site\": <sibling reader or a named reader from evidence>, \"use_op\": <harness use op>,\n"
    "   \"map_type\": <name or null>, \"mechanism\": <one sentence>,\n"
    "   \"confidence\": \"high|medium|low\", \"novelty\": \"novel|known-cve-shape\",\n"
    "   \"graph_facts_relied_on\": [<copied facts, e.g. 'free_site X is unguarded', "
    "'X reachable_from_syscall', 'use_site Y reads same object'>]}\n"
    "Prefer high-signal, reachable, RCU-deferred sites. Quality over quantity."
)


def _claude(prompt, model=None, timeout=240):
    cmd = ["claude", "-p", prompt, "--output-format", "json"]
    if model:
        cmd += ["--model", model]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return None, f"{e.__class__.__name__}"
    if p.returncode != 0:
        return None, (p.stderr or p.stdout or "nonzero exit")[:400]
    # envelope: {"result": "<text>", ...}
    try:
        env = json.loads(p.stdout)
        text = env.get("result", p.stdout)
    except json.JSONDecodeError:
        text = p.stdout
    return text, None


def _extract_json(text):
    """Pull the first {...} JSON object out of an LLM response."""
    a = text.find("{")
    b = text.rfind("}")
    if a < 0 or b < 0 or b < a:
        return None
    try:
        return json.loads(text[a:b + 1])
    except json.JSONDecodeError:
        return None


def cmd_hypothesize(args):
    with open(args.bundles) as f:
        data = json.load(f)
    bundles = data["bundles"]
    harness_ops = data["harness_ops"]

    # Batch bundles into the prompt (one agent call is cheapest; chunk if huge).
    prompt = (
        AGENT_SYSTEM + "\n\n=== harness_ops ===\n" + json.dumps(harness_ops) +
        "\n\n=== evidence bundles ===\n" + json.dumps(bundles, indent=1) +
        "\n\nProduce {\"hypotheses\":[...]} now."
    )
    print(f"hypothesize: sending {len(bundles)} bundles to claude -p ...", file=sys.stderr)
    text, err = _claude(prompt, model=args.model)
    if err:
        print(f"agent call failed: {err}", file=sys.stderr)
        return 2
    obj = _extract_json(text)
    if not obj or "hypotheses" not in obj:
        print("agent did not return parseable hypotheses; raw saved to .raw", file=sys.stderr)
        with open(args.out + ".raw", "w") as f:
            f.write(text)
        return 3
    hypos = obj["hypotheses"]
    with open(args.out, "w") as f:
        json.dump({"scan_id": data["scan_id"], "hypotheses": hypos}, f, indent=2)
    print(f"wrote {len(hypos)} hypotheses to {args.out}", file=sys.stderr)
    for h in hypos:
        print(f"  [{h.get('confidence','?'):6s}] {h.get('id','?')}: "
              f"{h.get('free_site','?')} vs {h.get('use_site','?')} "
              f"({h.get('novelty','?')})", file=sys.stderr)
    return 0


# ---------------- verify ----------------

def cmd_verify(args):
    with open(args.hypos) as f:
        data = json.load(f)
    sid = data["scan_id"]
    d = GraphDatabase.driver(URI, auth=AUTH)
    if not _wait(d):
        print("neo4j not reachable on 7688", file=sys.stderr)
        return 1
    guard_or = " OR ".join(f"g.name CONTAINS '{p}'" for p in GUARD_PATTERNS)
    read_or = " OR ".join(f"cc.name CONTAINS '{p}'" for p in READ_PATTERNS)

    out = []
    with d.session() as s:
        for h in data["hypotheses"]:
            checks = {}
            fs, us = h.get("free_site"), h.get("use_site")
            # 1) free_site exists
            checks["free_site_exists"] = bool(_one(s,
                "MATCH (m:CpgMethod {scan_id:$sid, full_name:$fn}) RETURN count(m) AS c",
                sid=sid, fn=fs))
            # 2) free_site truly unguarded (no guard call in body)
            checks["free_site_unguarded"] = (checks["free_site_exists"] and not bool(_one(s,
                f"MATCH (m:CpgMethod {{scan_id:$sid, full_name:$fn}})-[:CONTAINS_CALL]->"
                f"(g:CpgCall {{scan_id:$sid}}) WHERE ({guard_or}) RETURN count(g) AS c",
                sid=sid, fn=fs)))
            # 3) use_site exists and actually reads (has a read-pattern call)
            checks["use_site_exists"] = bool(_one(s,
                "MATCH (m:CpgMethod {scan_id:$sid, full_name:$fn}) RETURN count(m) AS c",
                sid=sid, fn=us))
            checks["use_site_reads"] = (checks["use_site_exists"] and bool(_one(s,
                f"MATCH (m:CpgMethod {{scan_id:$sid, full_name:$fn}})-[:CONTAINS_CALL]->"
                f"(cc:CpgCall {{scan_id:$sid}}) WHERE ({read_or}) RETURN count(cc) AS c",
                sid=sid, fn=us)))
            # 4) free_site reachable from a syscall entry (dispatch-aware, bounded)
            checks["free_site_reachable"] = bool(_one(s,
                "MATCH (e:EntryPoint {scan_id:$sid})-[:ENTERS_AT]->(em:CpgMethod {scan_id:$sid}) "
                "MATCH (em)-[:CONTAINS_CALL|RESOLVES_TO*1..6]->"
                "(:CpgCall {scan_id:$sid})-[:RESOLVES_TO]->(t:CpgMethod {scan_id:$sid, full_name:$fn}) "
                "RETURN count(t) AS c", sid=sid, fn=fs))
            passed = sum(1 for v in checks.values() if v)
            verdict = "CONFIRMED" if (checks["free_site_exists"] and checks["free_site_unguarded"]
                                      and checks["use_site_exists"]) else "UNSUPPORTED"
            h2 = dict(h)
            h2["verification"] = {"verdict": verdict, "checks": checks, "passed": passed}
            out.append(h2)
    d.close()
    with open(args.out, "w") as f:
        json.dump({"scan_id": sid, "hypotheses": out}, f, indent=2)
    conf = sum(1 for h in out if h["verification"]["verdict"] == "CONFIRMED")
    print(f"verified {len(out)} hypotheses: {conf} CONFIRMED, {len(out)-conf} UNSUPPORTED",
          file=sys.stderr)
    for h in out:
        v = h["verification"]
        print(f"  {v['verdict']:11s} {h.get('id','?')}  "
              f"(checks {v['passed']}/{len(v['checks'])})", file=sys.stderr)
    return 0


def _one(session, cypher, **params):
    r = session.run(cypher, **params).single()
    return r[0] if r else 0


# ---------------- emit ----------------

def cmd_emit(args):
    with open(args.verified) as f:
        data = json.load(f)
    os.makedirs(args.corpus, exist_ok=True)
    written = 0
    manifest = []
    for h in data["hypotheses"]:
        v = h.get("verification", {})
        if v.get("verdict") != "CONFIRMED":
            continue
        # The fuzzer drives via syscalls, so a free site the graph cannot reach
        # from any syscall entry is not a drivable target -- skip it (the agent
        # usually flags these itself and rates them low).
        if v.get("checks", {}).get("free_site_reachable") is False:
            print(f"  skip (not syscall-reachable): {h.get('id')}", file=sys.stderr)
            continue
        sub = h.get("subsystem")
        free_op, use_op = h.get("free_op"), h.get("use_op")
        if not (sub and free_op and use_op):
            continue
        tc = {
            "subsystem": sub,
            "pattern_id": "agentic_" + h.get("id", "hypo"),
            "op_a": {"type": free_op, "cpu": 0, "args": {"key": 1}},
            "op_b": {"type": use_op, "cpu": 2, "args": {"key": 1}},
            "delay_ns": args.window_ns,
            "iterations": args.iterations,
        }
        if sub == "bpf":
            mt = {"hash": 1, "array": 2, "percpu_hash": 5, "lru_hash": 9}.get(
                h.get("map_type") or "hash", 1)
            tc["setup"] = {"map_type": mt, "map_entries": 256, "key_size": 4, "value_size": 8}
            # spray the use side to reclaim/touch the freed slot -- makes a UAF/WAF
            # observable rather than a one-shot deref that usually misses the window.
            if use_op in ("map_lookup_elem", "map_update_elem", "map_delete_elem"):
                tc["spray"] = 8
        cid = tc["pattern_id"]
        with open(os.path.join(args.corpus, cid + ".json"), "w") as f:
            json.dump({"test": tc, "hypothesis": {
                "shared_object": h.get("shared_object"), "mechanism": h.get("mechanism"),
                "confidence": h.get("confidence"), "novelty": h.get("novelty"),
                "free_site": h.get("free_site"), "use_site": h.get("use_site"),
                "graph_facts_relied_on": h.get("graph_facts_relied_on"),
                "verification": v}}, f, indent=2)
        manifest.append({"id": cid, "confidence": h.get("confidence"),
                         "novelty": h.get("novelty"), "mechanism": h.get("mechanism")})
        written += 1
    with open(os.path.join(args.corpus, "manifest.json"), "w") as f:
        json.dump({"count": written, "cases": manifest}, f, indent=2)
    print(f"emitted {written} CONFIRMED agentic race targets to {args.corpus}", file=sys.stderr)
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("extract"); e.add_argument("--scan-id", required=True)
    e.add_argument("--out", default="bundles.json")
    e.add_argument("--limit", type=int, default=120, help="unguarded sites to scan")
    e.add_argument("--max-bundles", type=int, default=30, help="bundles kept for the agent")
    e.set_defaults(func=cmd_extract)

    h = sub.add_parser("hypothesize"); h.add_argument("--bundles", default="bundles.json")
    h.add_argument("--out", default="hypos.json"); h.add_argument("--model", default=None)
    h.set_defaults(func=cmd_hypothesize)

    v = sub.add_parser("verify"); v.add_argument("--scan-id", required=True)
    v.add_argument("--hypos", default="hypos.json"); v.add_argument("--out", default="verified.json")
    v.set_defaults(func=cmd_verify)

    m = sub.add_parser("emit"); m.add_argument("--verified", default="verified.json")
    m.add_argument("--corpus", default=os.path.expanduser("~/corpus-agentic"))
    m.add_argument("--window-ns", type=int, default=2000); m.add_argument("--iterations", type=int, default=41)
    m.set_defaults(func=cmd_emit)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
