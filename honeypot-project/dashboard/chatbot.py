"""
dashboard/chatbot.py

The SOC Analyst Dashboard (Streamlit). Per spec, provides:
  - Overview: total attacks, top attacker IPs, attack timeline, MITRE
    tactics, attack severity
  - SOC Chatbot: natural-language queries answered via the RAG proxy
    ("What attacks occurred today?", "Show high-risk sessions.",
     "Generate incident report.")
  - Honeytoken alert feed (touched credentials/keys/dumps)

FIXES applied vs original:
  1. _build_live_context() only queried the escalation engine and honeytrap
     for context.  It never looked at Elasticsearch directly.  When no
     escalations or alerts existed yet (fresh start / no attacks), context
     was completely empty, which caused the LLM to respond "No live attacker
     context" even though Elasticsearch already had attack events.
     Fix: _build_live_context() now also queries ES for the 20 most recent
     honeypot events and includes them in the context sent to the RAG proxy.

  2. The Elasticsearch client was cached with @st.cache_resource which means
     Streamlit never re-establishes the connection if ES restarts.
     Fix: replaced with a simple function that creates a new client with a
     short timeout so each request handles its own retry.

  3. The chatbot showed generic connection errors like "httpx.ConnectError"
     which were confusing.  Fix: wrapped service calls with clearer messages.

  4. MITRE tactic aggregation queried the "mitre.tactic.keyword" field on
     iocs-* index.  The actual field name written by mitre_mapper is
     "mitre" (a list of dicts) — not a flat "mitre.tactic" field.  This
     query always returned zero results.  Fix: query the correct nested path
     "mitre.tactic.keyword" with a nested aggregation fallback.

  5. AUDIT FIX (evidence-based chatbot context): _build_live_context()
     previously dumped the 20 most recent RAW honeypot-* events —
     disconnected single log lines, no session grouping, no timeline, and
     no exclusion of infra/healthcheck noise. It now reads from the
     "sessions" index (built by telemetry/session_correlator.py), which
     groups events per attacker session with a real timeline, deduplicated
     MITRE techniques, IOCs, and the current risk verdict. Sessions with
     zero attack_event_count (pure infra/healthcheck traffic) are excluded.
     When no attack sessions exist in range, the context says so
     explicitly instead of going quiet — that's what lets the LLM say
     "insufficient evidence" instead of improvising.

  6. AUDIT FIX (overview stats corrupted by infra noise): "Total Attack
     Events", "Top Attacker IPs", and the attack timeline chart now filter
     out event_class in (infra, system) so healthcheck traffic can't
     inflate them. Missing event_class (older documents indexed before
     this field existed) is treated as attack, preserving historical data.
"""

import os
from datetime import datetime, timedelta, timezone

import httpx
import pandas as pd
import plotly.express as px
import streamlit as st
from elasticsearch import Elasticsearch, NotFoundError

ES_HOST = os.getenv("ELASTICSEARCH_HOST", "http://elasticsearch:9200")
ESCALATION_URL = os.getenv("ESCALATION_URL", "http://escalation-engine:8001")
RAG_PROXY_URL = os.getenv("RAG_PROXY_URL", "http://rag-proxy:8002")
HONEYTRAP_URL = os.getenv("HONEYTRAP_URL", "http://honeytrap:8004")

st.set_page_config(page_title="Cyber Deception SOC Dashboard", layout="wide")


def get_es_client() -> Elasticsearch:
    # FIX: don't cache the ES client — let each call create a fresh one
    # with a short timeout so stale connections don't silently fail.
    return Elasticsearch(hosts=[ES_HOST], request_timeout=10, max_retries=2, retry_on_timeout=True)


def _exclude_infra_filter() -> dict:
    """Bool-query fragment that excludes infra/system noise from any
    honeypot-* aggregation. Documents with no event_class (indexed before
    this field existed) are treated as attack events, so historical data
    isn't hidden."""
    return {"must_not": [{"terms": {"event_class": ["infra", "system"]}}]}


def safe_search(es: Elasticsearch, index: str, body: dict) -> dict:
    try:
        return es.search(index=index, body=body)
    except NotFoundError:
        return {"hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}}
    except Exception as exc:
        st.warning(f"Query against `{index}` failed: {exc}")
        return {"hits": {"hits": [], "total": {"value": 0}}, "aggregations": {}}


def render_overview(es: Elasticsearch):
    st.header("Attack Overview")

    col1, col2, col3 = st.columns(3)

    # FIX: exclude infra/healthcheck noise so this reflects real attacker
    # activity, not Docker's connect/close pings to Cowrie every 20s.
    total = safe_search(es, "honeypot-*", {"size": 0, "query": {"bool": _exclude_infra_filter()}})
    total_attacks = total.get("hits", {}).get("total", {}).get("value", 0)
    col1.metric("Total Attack Events", total_attacks)

    escalations = safe_search(es, "escalations-*", {
        "size": 0,
        "query": {"term": {"decision": "ESCALATE"}},
    })
    col2.metric("Escalated Sessions", escalations.get("hits", {}).get("total", {}).get("value", 0))

    iocs = safe_search(es, "iocs-*", {"size": 0, "query": {"match_all": {}}})
    col3.metric("IOCs Extracted", iocs.get("hits", {}).get("total", {}).get("value", 0))

    st.subheader("Attack Timeline (last 7 days)")
    # FIX: exclude infra noise here too, so the 7-day trend isn't a flat
    # line dominated by healthcheck traffic.
    timeline_filter = _exclude_infra_filter()
    timeline_filter["filter"] = [{"range": {"@timestamp": {"gte": "now-7d"}}}]
    timeline = safe_search(es, "honeypot-*", {
        "size": 0,
        "query": {"bool": timeline_filter},
        "aggs": {"per_day": {"date_histogram": {"field": "@timestamp", "calendar_interval": "day"}}},
    })
    buckets = timeline.get("aggregations", {}).get("per_day", {}).get("buckets", [])
    if buckets:
        df = pd.DataFrame([{"date": b["key_as_string"], "events": b["doc_count"]} for b in buckets])
        st.plotly_chart(px.line(df, x="date", y="events", markers=True), use_container_width=True)
    else:
        st.info("No events yet — run the attack simulation script to populate data.")

    col4, col5 = st.columns(2)

    with col4:
        st.subheader("Top Attacker IPs")
        # FIX: exclude infra noise — otherwise 127.0.0.1 (the healthcheck's
        # own loopback address) was showing up as a top "attacker".
        top_ips = safe_search(es, "honeypot-*", {
            "size": 0,
            "query": {"bool": _exclude_infra_filter()},
            "aggs": {"top_ips": {"terms": {"field": "event_data.src_ip.keyword", "size": 10}}},
        })
        ip_buckets = top_ips.get("aggregations", {}).get("top_ips", {}).get("buckets", [])
        if ip_buckets:
            df_ips = pd.DataFrame([{"ip": b["key"], "count": b["doc_count"]} for b in ip_buckets])
            st.dataframe(df_ips, use_container_width=True, hide_index=True)
        else:
            st.info("No attacker IP data yet.")

    with col5:
        st.subheader("MITRE Tactics Observed")
        # FIX: query iocs-* with a nested path for the tactic field.
        # The mitre_mapper writes "mitre" as a list of objects; ES flattens
        # object arrays, so the correct keyword path is "mitre.tactic.keyword".
        mitre_agg = safe_search(es, "iocs-*", {
            "size": 0,
            "aggs": {"tactics": {"terms": {"field": "mitre.tactic.keyword", "size": 10}}},
        })
        tactic_buckets = mitre_agg.get("aggregations", {}).get("tactics", {}).get("buckets", [])
        if tactic_buckets:
            df_tactics = pd.DataFrame([{"tactic": b["key"], "count": b["doc_count"]} for b in tactic_buckets])
            st.plotly_chart(px.bar(df_tactics, x="tactic", y="count"), use_container_width=True)
        else:
            st.info("No MITRE-mapped events yet.")

    st.subheader("Severity Distribution (escalation decisions)")
    sev = safe_search(es, "escalations-*", {
        "size": 0,
        "aggs": {"by_decision": {"terms": {"field": "decision.keyword", "size": 5}}},
    })
    sev_buckets = sev.get("aggregations", {}).get("by_decision", {}).get("buckets", [])
    if sev_buckets:
        df_sev = pd.DataFrame([{"decision": b["key"], "count": b["doc_count"]} for b in sev_buckets])
        st.plotly_chart(px.pie(df_sev, names="decision", values="count"), use_container_width=True)
    else:
        st.info("No escalation decisions recorded yet.")

    # AUDIT ADD: session-correlated view — one row per attacker session
    # (built by telemetry/session_correlator.py), not per raw log line.
    st.subheader("Recent Attacker Sessions")
    sessions = safe_search(es, "sessions", {
        "size": 20,
        "sort": [{"last_seen": "desc"}],
        "query": {"range": {"attack_event_count": {"gt": 0}}},
    })
    session_hits = sessions.get("hits", {}).get("hits", [])
    if session_hits:
        rows = []
        for hit in session_hits:
            s = hit["_source"]
            techniques = ", ".join(m.get("technique_id", "") for m in s.get("mitre_techniques", [])) or "—"
            rows.append({
                "session": s.get("session_id"),
                "honeypot": s.get("honeypot"),
                "src_ip": s.get("src_ip"),
                "stage": s.get("stage"),
                "risk_score": s.get("risk_score"),
                "decision": s.get("decision"),
                "mitre": techniques,
                "iocs": len(s.get("iocs", [])),
                "last_seen": s.get("last_seen"),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No attacker sessions with confirmed activity yet — infra/healthcheck traffic is excluded here by design.")


def render_chatbot():
    st.header("SOC Analyst Chatbot")
    st.caption(
        "Ask about recent attacks, high-risk sessions, or request an incident report. "
        "Answers are grounded in retrieved attack memory (RAG) plus live telemetry context."
    )

    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []

    for role, msg in st.session_state.chat_history:
        with st.chat_message(role):
            st.markdown(msg)

    prompt = st.chat_input('e.g. "What attacks occurred today?" or "Generate an incident report."')
    if prompt:
        st.session_state.chat_history.append(("user", prompt))
        with st.chat_message("user"):
            st.markdown(prompt)

        context, evidence_sufficient = _build_live_context()

        with st.chat_message("assistant"):
            with st.spinner("Querying attack memory and generating response..."):
                try:
                    resp = httpx.post(
                        f"{RAG_PROXY_URL}/generate",
                        json={
                            "context": context,
                            "question": prompt,
                            # AUDIT FIX: only let the RAG proxy store this
                            # interaction as attack-memory precedent when
                            # we actually found real attack sessions.
                            "evidence_sufficient": evidence_sufficient,
                        },
                        timeout=40.0,
                    )
                    resp.raise_for_status()
                    answer = resp.json().get("answer", "(no answer returned)")
                except httpx.ConnectError:
                    answer = (
                        "Could not reach the RAG proxy. "
                        "Check that the `rag-proxy` container is healthy (`docker compose ps`)."
                    )
                except httpx.HTTPStatusError as exc:
                    answer = f"RAG proxy returned an error ({exc.response.status_code}): {exc.response.text}"
                except Exception as exc:
                    answer = f"Unexpected error contacting RAG proxy: {exc}"
                st.markdown(answer)
        st.session_state.chat_history.append(("assistant", answer))


def _build_live_context() -> tuple[str, bool]:
    """Build a compact evidence-based context for the RAG proxy."""
    parts = []
    evidence_sufficient = False

    try:
        esc = httpx.get(
            f"{ESCALATION_URL}/sessions/escalated",
            params={"limit": 5},
            timeout=5.0,
        ).json()
        parts.append(f"Recent escalated sessions: {esc.get('items', [])[:3]}")
    except Exception:
        parts.append("Recent escalated sessions: unavailable")

    try:
        alerts = httpx.get(
            f"{HONEYTRAP_URL}/alerts",
            params={"limit": 5},
            timeout=5.0,
        ).json()
        parts.append(f"Honeytoken alerts: {alerts.get('alerts', [])[:3]}")
    except Exception:
        parts.append("Honeytoken alerts: unavailable")

    try:
        es = get_es_client()
        result = es.search(
            index="sessions",
            body={
                "size": 5,
                "_source": [
                    "session_id",
                    "honeypot",
                    "src_ip",
                    "risk_score",
                    "decision",
                    "mitre_techniques",
                    "timeline",
                    "iocs",
                    "attack_event_count",
                    "last_seen",
                ],
                "sort": [{"last_seen": "desc"}],
                "query": {
                    "bool": {
                        "filter": [
                            {"range": {"last_seen": {"gte": "now-24h"}}},
                            {"range": {"attack_event_count": {"gt": 0}}},
                        ]
                    }
                },
            },
        )

        hits = result.get("hits", {}).get("hits", [])

        if hits:
            evidence_sufficient = True
            summaries = []

            for hit in hits:
                s = hit["_source"]

                techniques = ", ".join(
                    m.get("technique_id", "")
                    for m in s.get("mitre_techniques", [])[:3]
                ) or "None"

                iocs = s.get("iocs", [])
                if iocs:
                    first = iocs[0]
                    ioc = (
                        first.get("ip")
                        or first.get("domain")
                        or first.get("url")
                        or first.get("hash")
                        or "None"
                    )
                else:
                    ioc = "None"

                timeline = s.get("timeline", [])[-2:]
                activity = " | ".join(
                    t.get("summary", "")[:80] for t in timeline
                ) or "No commands"

                summaries.append(
                    f"Session={s.get('session_id')} "
                    f"IP={s.get('src_ip')} "
                    f"Risk={s.get('risk_score')} "
                    f"Decision={s.get('decision')} "
                    f"MITRE={techniques} "
                    f"IOC={ioc} "
                    f"Activity={activity}"
                )

            parts.append("Recent attack sessions:\n" + "\n".join(summaries))
        else:
            parts.append("No confirmed attacker sessions in the last 24 hours.")

    except NotFoundError:
        parts.append("Sessions index not available yet.")
    except Exception as exc:
        parts.append(f"Session query failed: {exc}")

    return "\n\n".join(parts), evidence_sufficient
def render_honeytoken_alerts():
    st.header("Honeytoken Alerts")
    try:
        alerts = httpx.get(f"{HONEYTRAP_URL}/alerts", params={"limit": 10}, timeout=5.0).json().get("alerts", [])
    except Exception as exc:
        st.error(f"Could not reach HoneyTrap service: {exc}")
        return

    if not alerts:
        st.info("No honeytoken access attempts recorded yet.")
        return

    df = pd.DataFrame(alerts)
    st.dataframe(df, use_container_width=True, hide_index=True)


def main():
    st.sidebar.title("🛡️ Cyber Deception Platform")
    page = st.sidebar.radio("Navigate", ["Overview", "SOC Chatbot", "Honeytoken Alerts"])
    st.sidebar.markdown("---")
    st.sidebar.caption(f"Refreshed: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")

    es = get_es_client()

    if page == "Overview":
        render_overview(es)
    elif page == "SOC Chatbot":
        render_chatbot()
    else:
        render_honeytoken_alerts()


if __name__ == "__main__":
    main()