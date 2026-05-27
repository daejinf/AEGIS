import json
import os
import time
from datetime import datetime
from html import escape

import pandas as pd
import streamlit as st


LOG_FILE = "live_dashboard.json"
REFRESH_SECONDS = 2

LABEL_META = {
    0: {"name": "정상", "headline": "정상 흐름 유지", "tone": "safe", "risk": 8},
    1: {"name": "ICMP Flood", "headline": "ICMP Flood 감지", "tone": "danger", "risk": 92},
    2: {"name": "Port Scan", "headline": "Port Scan 감지", "tone": "warn", "risk": 74},
    3: {"name": "SSH Brute Force", "headline": "SSH Brute Force 감지", "tone": "danger", "risk": 86},
    4: {"name": "ARP Spoofing", "headline": "ARP Spoofing 감지", "tone": "danger", "risk": 90},
    5: {"name": "DNS Anomaly", "headline": "DNS Anomaly 감지", "tone": "warn", "risk": 68},
}

TONE_META = {
    "safe": {"bg": "#ecfdf3", "fg": "#027a48", "line": "#12b76a", "soft": "#d1fadf"},
    "warn": {"bg": "#fff7ed", "fg": "#c2410c", "line": "#f97316", "soft": "#fed7aa"},
    "danger": {"bg": "#fef2f2", "fg": "#b42318", "line": "#ef4444", "soft": "#fecaca"},
}

SIGNAL_LABELS = [
    ("total_pkt_cnt", "전체 패킷"),
    ("tcp_cnt", "TCP"),
    ("udp_cnt", "UDP"),
    ("icmp_cnt", "ICMP"),
    ("dns_query_cnt", "DNS 질의"),
    ("failed_login_cnt", "SSH 실패"),
    ("unique_dst_port_cnt", "대상 포트"),
    ("unique_src_ip_cnt", "출발지 IP"),
]


st.set_page_config(page_title="AEGIS", page_icon="A", layout="wide")


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Pretendard:wght@400;500;600;700;800&display=swap');

        :root {
            --bg: #f4f7fb;
            --surface: rgba(255, 255, 255, 0.90);
            --surface-solid: #ffffff;
            --text: #111827;
            --muted: #6b7280;
            --blue: #0064ff;
            --blue-soft: #eaf2ff;
            --stroke: rgba(17, 24, 39, 0.08);
            --shadow: 0 24px 60px rgba(15, 23, 42, 0.08);
            --radius-hero: 32px;
            --radius-card: 26px;
            --radius-mini: 20px;
        }

        .stApp {
            background:
                radial-gradient(circle at top left, rgba(0, 100, 255, 0.10), transparent 24%),
                radial-gradient(circle at top right, rgba(125, 211, 252, 0.18), transparent 26%),
                linear-gradient(180deg, #f8fbff 0%, var(--bg) 52%, #eef3fa 100%);
            color: var(--text);
        }

        html, body, [class*="css"] {
            font-family: "Pretendard", "SF Pro Display", "Segoe UI", sans-serif;
            color: var(--text);
        }

        .block-container {
            max-width: 1380px;
            padding-top: 1.6rem;
            padding-bottom: 2.4rem;
        }

        [data-testid="stHeader"] {
            background: transparent;
        }

        [data-testid="stToolbar"] {
            right: 1rem;
        }

        .hero-shell,
        .surface-shell {
            background: var(--surface);
            backdrop-filter: blur(22px);
            border: 1px solid var(--stroke);
            box-shadow: var(--shadow);
        }

        .hero-shell {
            border-radius: var(--radius-hero);
            padding: 34px 34px 30px 34px;
            margin-bottom: 20px;
            position: relative;
            overflow: hidden;
        }

        .hero-shell::after {
            content: "";
            position: absolute;
            right: -40px;
            bottom: -40px;
            width: 220px;
            height: 220px;
            border-radius: 999px;
            background: radial-gradient(circle, rgba(0, 100, 255, 0.14), rgba(0, 100, 255, 0));
        }

        .hero-grid {
            display: grid;
            grid-template-columns: minmax(0, 1.35fr) 260px;
            gap: 24px;
            align-items: center;
        }

        .eyebrow {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 8px 12px;
            border-radius: 999px;
            background: var(--blue-soft);
            color: var(--blue);
            font-size: 0.78rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .hero-title {
            margin: 18px 0 10px 0;
            font-size: 3.4rem;
            line-height: 0.98;
            letter-spacing: -0.06em;
            font-weight: 800;
            color: var(--text);
        }

        .hero-sub {
            margin: 0;
            color: var(--muted);
            font-size: 1rem;
            font-weight: 500;
            line-height: 1.65;
        }

        .chip-row {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 22px;
        }

        .chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 14px;
            border-radius: 999px;
            background: rgba(255, 255, 255, 0.92);
            border: 1px solid rgba(17, 24, 39, 0.06);
            color: #1f2937;
            font-size: 0.92rem;
            font-weight: 600;
        }

        .chip-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--blue);
        }

        .risk-wrap {
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .risk-ring {
            width: 210px;
            height: 210px;
            border-radius: 999px;
            display: grid;
            place-items: center;
            background: conic-gradient(var(--ring-color) calc(var(--risk) * 1%), rgba(17, 24, 39, 0.08) 0);
            position: relative;
        }

        .risk-ring::before {
            content: "";
            position: absolute;
            inset: 16px;
            background: rgba(255, 255, 255, 0.95);
            border-radius: 999px;
            box-shadow: inset 0 1px 0 rgba(255,255,255,0.8);
        }

        .risk-core {
            position: relative;
            z-index: 2;
            text-align: center;
        }

        .risk-number {
            display: block;
            font-size: 3rem;
            line-height: 1;
            font-weight: 800;
            letter-spacing: -0.06em;
            color: var(--text);
        }

        .risk-caption {
            margin-top: 8px;
            display: block;
            color: var(--muted);
            font-size: 0.92rem;
            font-weight: 700;
        }

        .risk-status {
            margin-top: 10px;
            display: inline-flex;
            padding: 7px 12px;
            border-radius: 999px;
            font-size: 0.86rem;
            font-weight: 800;
            background: var(--tone-bg);
            color: var(--tone-fg);
        }

        .stat-card,
        .surface-shell {
            border-radius: var(--radius-card);
        }

        .stat-card {
            background: rgba(255, 255, 255, 0.88);
            border: 1px solid var(--stroke);
            box-shadow: var(--shadow);
            padding: 22px 22px 20px 22px;
            min-height: 138px;
        }

        .stat-label {
            color: var(--muted);
            font-size: 0.9rem;
            font-weight: 700;
            margin-bottom: 16px;
        }

        .stat-value {
            color: var(--text);
            font-size: 2.2rem;
            line-height: 1;
            font-weight: 800;
            letter-spacing: -0.05em;
        }

        .stat-foot {
            margin-top: 10px;
            color: var(--muted);
            font-size: 0.94rem;
            line-height: 1.55;
        }

        .surface-shell {
            padding: 24px;
            height: 100%;
        }

        .section-kicker {
            color: var(--muted);
            font-size: 0.82rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .section-title {
            margin: 8px 0 18px 0;
            font-size: 1.35rem;
            line-height: 1.15;
            letter-spacing: -0.03em;
            font-weight: 800;
            color: var(--text);
        }

        .mix-row {
            margin-bottom: 16px;
        }

        .mix-row:last-child {
            margin-bottom: 0;
        }

        .mix-head {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 0.96rem;
            font-weight: 700;
            color: var(--text);
        }

        .mix-track {
            width: 100%;
            height: 11px;
            border-radius: 999px;
            background: rgba(17, 24, 39, 0.06);
            overflow: hidden;
        }

        .mix-fill {
            height: 100%;
            border-radius: 999px;
        }

        .signal-grid {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 12px;
        }

        .signal-box {
            padding: 18px 18px 16px 18px;
            border-radius: var(--radius-mini);
            background: linear-gradient(180deg, rgba(255,255,255,0.98), rgba(244,247,251,0.96));
            border: 1px solid rgba(17, 24, 39, 0.06);
        }

        .signal-label {
            color: var(--muted);
            font-size: 0.88rem;
            font-weight: 700;
            margin-bottom: 10px;
        }

        .signal-value {
            font-size: 2rem;
            font-weight: 800;
            line-height: 1;
            letter-spacing: -0.05em;
            color: var(--text);
        }

        .feed-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 14px 0;
            border-bottom: 1px solid rgba(17, 24, 39, 0.06);
        }

        .feed-item:first-child {
            padding-top: 0;
        }

        .feed-item:last-child {
            border-bottom: 0;
            padding-bottom: 0;
        }

        .feed-name {
            color: var(--text);
            font-size: 1rem;
            font-weight: 800;
            line-height: 1.2;
        }

        .feed-meta {
            margin-top: 6px;
            color: var(--muted);
            font-size: 0.9rem;
            font-weight: 600;
        }

        .feed-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 72px;
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 0.84rem;
            font-weight: 800;
            white-space: nowrap;
        }

        .ledger-shell {
            margin-top: 20px;
        }

        .ledger-table-wrap {
            overflow-x: auto;
            border-radius: 22px;
            border: 1px solid rgba(17, 24, 39, 0.07);
            background: rgba(255,255,255,0.92);
        }

        table.ledger-table {
            width: 100%;
            min-width: 920px;
            border-collapse: collapse;
        }

        .ledger-table thead th {
            position: sticky;
            top: 0;
            padding: 16px 18px;
            text-align: left;
            font-size: 0.84rem;
            font-weight: 800;
            letter-spacing: 0.04em;
            text-transform: uppercase;
            color: #6b7280;
            background: rgba(248, 250, 252, 0.96);
            border-bottom: 1px solid rgba(17, 24, 39, 0.08);
        }

        .ledger-table tbody td {
            padding: 16px 18px;
            font-size: 0.95rem;
            font-weight: 600;
            color: #1f2937;
            border-bottom: 1px solid rgba(17, 24, 39, 0.06);
        }

        .ledger-table tbody tr:last-child td {
            border-bottom: 0;
        }

        .ledger-table tbody tr:hover td {
            background: rgba(0, 100, 255, 0.03);
        }

        .ledger-badge {
            display: inline-flex;
            align-items: center;
            padding: 7px 11px;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 800;
        }

        .empty-shell {
            padding: 70px 32px;
            text-align: center;
            border-radius: var(--radius-hero);
            background: rgba(255,255,255,0.86);
            border: 1px dashed rgba(17,24,39,0.12);
            box-shadow: var(--shadow);
        }

        .empty-title {
            color: var(--text);
            font-size: 1.6rem;
            font-weight: 800;
            letter-spacing: -0.04em;
            margin-bottom: 10px;
        }

        .empty-copy {
            color: var(--muted);
            font-size: 1rem;
            font-weight: 600;
        }

        @media (max-width: 1100px) {
            .hero-grid {
                grid-template-columns: 1fr;
            }

            .hero-title {
                font-size: 2.7rem;
            }

            .risk-wrap {
                justify-content: flex-start;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def load_data() -> pd.DataFrame:
    records = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line:
                    records.append(json.loads(line))
    return pd.DataFrame(records)


def format_timestamp(raw_value) -> str:
    if pd.isna(raw_value):
        return "-"

    if isinstance(raw_value, str):
        stripped = raw_value.strip()
        if stripped.isdigit():
            raw_value = int(stripped)
        else:
            return stripped

    try:
        return datetime.fromtimestamp(int(raw_value)).strftime("%H:%M:%S")
    except (TypeError, ValueError, OSError):
        return str(raw_value)


def normalize_data(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df

    normalized = df.copy()
    numeric_columns = [
        "label",
        "confidence",
        "total_pkt_cnt",
        "tcp_cnt",
        "udp_cnt",
        "icmp_cnt",
        "dns_query_cnt",
        "failed_login_cnt",
        "unique_dst_port_cnt",
        "unique_src_ip_cnt",
    ]
    for column in numeric_columns:
        if column in normalized.columns:
            normalized[column] = pd.to_numeric(normalized[column], errors="coerce")

    normalized["label"] = normalized.get("label", 0).fillna(0).astype(int)
    normalized["confidence"] = normalized.get("confidence", 0).fillna(0).astype(float)
    normalized["display_time"] = normalized["timestamp"].map(format_timestamp)
    normalized["status_name"] = normalized["label"].map(
        lambda value: LABEL_META.get(value, LABEL_META[0])["name"]
    )
    normalized["headline"] = normalized["label"].map(
        lambda value: LABEL_META.get(value, LABEL_META[0])["headline"]
    )
    normalized["tone"] = normalized["label"].map(
        lambda value: LABEL_META.get(value, LABEL_META[0])["tone"]
    )
    normalized["risk_score"] = normalized["label"].map(
        lambda value: LABEL_META.get(value, LABEL_META[0])["risk"]
    )
    normalized["confidence_pct"] = (normalized["confidence"] * 100).round(1)
    return normalized


def build_stat_card(title: str, value: str, foot: str) -> str:
    return f"""
    <div class="stat-card">
        <div class="stat-label">{escape(title)}</div>
        <div class="stat-value">{escape(value)}</div>
        <div class="stat-foot">{escape(foot)}</div>
    </div>
    """


def build_attack_mix(df: pd.DataFrame) -> str:
    counts = df["label"].value_counts().to_dict()
    max_count = max(counts.values()) if counts else 1
    ordered_labels = [1, 3, 4, 2, 5, 0]
    rows = []
    for label in ordered_labels:
        meta = LABEL_META[label]
        tone = TONE_META[meta["tone"]]
        count = counts.get(label, 0)
        width = 0 if max_count == 0 else max(10, int((count / max_count) * 100)) if count else 0
        rows.append(
            f"""
            <div class="mix-row">
                <div class="mix-head">
                    <span>{escape(meta['name'])}</span>
                    <span>{count}</span>
                </div>
                <div class="mix-track">
                    <div class="mix-fill" style="width:{width}%;background:{tone['line']};"></div>
                </div>
            </div>
            """
        )
    return "".join(rows)


def build_signal_grid(latest_row: pd.Series) -> str:
    cards = []
    for column, label in SIGNAL_LABELS:
        value = int(latest_row.get(column, 0) or 0)
        cards.append(
            f"""
            <div class="signal-box">
                <div class="signal-label">{escape(label)}</div>
                <div class="signal-value">{value:,}</div>
            </div>
            """
        )
    return "".join(cards)


def build_recent_feed(df: pd.DataFrame) -> str:
    rows = []
    for _, row in df.head(6).iterrows():
        tone = TONE_META[row["tone"]]
        confidence = f"{row['confidence_pct']:.0f}%" if row["confidence_pct"] else "-"
        rows.append(
            f"""
            <div class="feed-item">
                <div>
                    <div class="feed-name">{escape(str(row['status_name']))}</div>
                    <div class="feed-meta">{escape(str(row['display_time']))} · confidence {confidence}</div>
                </div>
                <span class="feed-pill" style="background:{tone['bg']};color:{tone['fg']};">
                    {int(row['risk_score'])}
                </span>
            </div>
            """
        )
    return "".join(rows)


def build_ledger(df: pd.DataFrame) -> str:
    latest_rows = df.iloc[::-1].head(10).copy()
    table_rows = []
    for _, row in latest_rows.iterrows():
        tone = TONE_META[row["tone"]]
        table_rows.append(
            f"""
            <tr>
                <td>{escape(str(row['display_time']))}</td>
                <td>
                    <span class="ledger-badge" style="background:{tone['bg']};color:{tone['fg']};">
                        {escape(str(row['status_name']))}
                    </span>
                </td>
                <td>{row['confidence_pct']:.0f}%</td>
                <td>{int(row['risk_score'])}</td>
                <td>{int(row.get('total_pkt_cnt', 0) or 0):,}</td>
                <td>{int(row.get('tcp_cnt', 0) or 0):,}</td>
                <td>{int(row.get('udp_cnt', 0) or 0):,}</td>
                <td>{int(row.get('icmp_cnt', 0) or 0):,}</td>
                <td>{int(row.get('dns_query_cnt', 0) or 0):,}</td>
                <td>{int(row.get('failed_login_cnt', 0) or 0):,}</td>
            </tr>
            """
        )

    return f"""
    <div class="surface-shell ledger-shell">
        <div class="section-kicker">Ledger</div>
        <div class="section-title">최근 이벤트 로그</div>
        <div class="ledger-table-wrap">
            <table class="ledger-table">
                <thead>
                    <tr>
                        <th>시간</th>
                        <th>유형</th>
                        <th>신뢰도</th>
                        <th>리스크</th>
                        <th>패킷</th>
                        <th>TCP</th>
                        <th>UDP</th>
                        <th>ICMP</th>
                        <th>DNS</th>
                        <th>SSH</th>
                    </tr>
                </thead>
                <tbody>
                    {''.join(table_rows)}
                </tbody>
            </table>
        </div>
    </div>
    """


inject_styles()

placeholder = st.empty()

with placeholder.container():
    df = normalize_data(load_data())

    if df.empty:
        st.markdown(
            """
            <div class="empty-shell">
                <div class="empty-title">라이브 데이터 대기 중</div>
                <div class="empty-copy">Extractor, predictor, monitor가 순서대로 실행되면 이 화면이 즉시 채워집니다.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        latest = df.iloc[-1]
        latest_meta = LABEL_META.get(int(latest["label"]), LABEL_META[0])
        latest_tone = TONE_META[latest["tone"]]
        attack_count = int((df["label"] != 0).sum())
        attack_ratio = (attack_count / len(df)) * 100 if len(df) else 0
        average_confidence = df["confidence_pct"].replace(0, pd.NA).dropna().mean()
        average_confidence_text = f"{average_confidence:.1f}%" if pd.notna(average_confidence) else "-"

        st.markdown(
            f"""
            <div class="hero-shell">
                <div class="hero-grid">
                    <div>
                        <span class="eyebrow">AEGIS · LIVE SECURITY</span>
                        <div class="hero-title">{escape(latest_meta['headline'])}</div>
                        <p class="hero-sub">
                            최근 탐지 {escape(str(latest['display_time']))} · confidence {latest['confidence_pct']:.0f}% ·
                            실시간 패킷과 예측 결과를 가장 먼저 읽히는 순서로 정리했습니다.
                        </p>
                        <div class="chip-row">
                            <span class="chip"><span class="chip-dot"></span>Auto Refresh {REFRESH_SECONDS}s</span>
                            <span class="chip">누적 이벤트 {len(df):,}</span>
                            <span class="chip">공격 비중 {attack_ratio:.0f}%</span>
                        </div>
                    </div>
                    <div class="risk-wrap">
                        <div
                            class="risk-ring"
                            style="--risk:{int(latest['risk_score'])};--ring-color:{latest_tone['line']};--tone-bg:{latest_tone['bg']};--tone-fg:{latest_tone['fg']};"
                        >
                            <div class="risk-core">
                                <span class="risk-number">{int(latest['risk_score'])}</span>
                                <span class="risk-caption">Risk Score</span>
                                <span class="risk-status">{escape(latest_meta['name'])}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        stat_columns = st.columns(4)
        stat_html = [
            build_stat_card("현재 상태", latest_meta["name"], f"최근 탐지 {latest['display_time']}"),
            build_stat_card("누적 이벤트", f"{len(df):,}", "관제 파이프라인 총 기록 수"),
            build_stat_card("공격 비중", f"{attack_ratio:.0f}%", f"정상 제외 {attack_count:,}건"),
            build_stat_card("평균 신뢰도", average_confidence_text, "confidence 기준 평균"),
        ]
        for column, card in zip(stat_columns, stat_html):
            with column:
                st.markdown(card, unsafe_allow_html=True)

        top_columns = st.columns([0.95, 1.1, 0.95])

        with top_columns[0]:
            st.markdown(
                f"""
                <div class="surface-shell">
                    <div class="section-kicker">Attack Mix</div>
                    <div class="section-title">유형별 분포</div>
                    {build_attack_mix(df)}
                </div>
                """,
                unsafe_allow_html=True,
            )

        with top_columns[1]:
            st.markdown(
                f"""
                <div class="surface-shell">
                    <div class="section-kicker">Latest Snapshot</div>
                    <div class="section-title">실시간 특징값</div>
                    <div class="signal-grid">
                        {build_signal_grid(latest)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with top_columns[2]:
            st.markdown(
                f"""
                <div class="surface-shell">
                    <div class="section-kicker">Recent Feed</div>
                    <div class="section-title">최근 이벤트</div>
                    {build_recent_feed(df.iloc[::-1].reset_index(drop=True))}
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown(build_ledger(df), unsafe_allow_html=True)

time.sleep(REFRESH_SECONDS)
st.rerun()
