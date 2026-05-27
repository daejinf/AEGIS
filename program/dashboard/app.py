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
    0: {"name": "정상", "tone": "safe", "risk": 8},
    1: {"name": "ICMP Flood", "tone": "danger", "risk": 92},
    2: {"name": "Port Scan", "tone": "warn", "risk": 74},
    3: {"name": "SSH Brute Force", "tone": "danger", "risk": 86},
    4: {"name": "ARP Spoofing", "tone": "danger", "risk": 90},
    5: {"name": "DNS Anomaly", "tone": "warn", "risk": 68},
}

TONE_META = {
    "safe": {"bg": "#E8F8EE", "fg": "#0F9F59", "line": "#22C55E"},
    "warn": {"bg": "#FFF4E8", "fg": "#F97316", "line": "#F97316"},
    "danger": {"bg": "#FEECEC", "fg": "#E5484D", "line": "#EF4444"},
}

SIGNAL_ITEMS = [
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
            --bg: #F2F4F6;
            --surface: rgba(255, 255, 255, 0.96);
            --line: rgba(2, 32, 71, 0.08);
            --text: #191F28;
            --subtle: #6B7684;
            --muted: #8B95A1;
            --blue: #3182F6;
            --blue-soft: #EAF2FF;
            --shadow: 0 24px 54px rgba(2, 32, 71, 0.08);
            --radius-xl: 30px;
            --radius-lg: 24px;
            --radius-md: 18px;
        }

        .stApp {
            background:
                radial-gradient(circle at top right, rgba(49, 130, 246, 0.10), transparent 24%),
                linear-gradient(180deg, #F8FBFF 0%, var(--bg) 55%, #EDF2F7 100%);
        }

        html, body, [class*="css"] {
            font-family: "Pretendard", "SF Pro Display", "Segoe UI", sans-serif;
            color: var(--text);
        }

        .block-container {
            max-width: 1320px;
            padding-top: 1.5rem;
            padding-bottom: 2.5rem;
        }

        [data-testid="stHeader"] {
            background: transparent;
        }

        .card {
            background: var(--surface);
            border: 1px solid var(--line);
            box-shadow: var(--shadow);
            border-radius: var(--radius-xl);
        }

        .hero {
            padding: 28px 30px;
            margin-bottom: 18px;
        }

        .hero-grid {
            display: grid;
            grid-template-columns: minmax(0, 1.25fr) 280px;
            gap: 22px;
            align-items: center;
        }

        .hero-kicker {
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
            margin: 16px 0 8px 0;
            font-size: 3.15rem;
            line-height: 0.98;
            letter-spacing: -0.07em;
            font-weight: 800;
        }

        .hero-desc {
            color: var(--subtle);
            font-size: 1rem;
            font-weight: 600;
            line-height: 1.58;
            margin: 0;
        }

        .chip-row {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 20px;
        }

        .chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 14px;
            border-radius: 999px;
            background: #FFFFFF;
            border: 1px solid rgba(2, 32, 71, 0.06);
            color: var(--text);
            font-size: 0.92rem;
            font-weight: 700;
        }

        .chip-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--blue);
        }

        .hero-side {
            padding: 22px;
            border-radius: 24px;
            background: linear-gradient(180deg, #FFFFFF, #F8FBFF);
            border: 1px solid rgba(2, 32, 71, 0.06);
        }

        .side-label {
            color: var(--muted);
            font-size: 0.84rem;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .side-value {
            color: var(--text);
            font-size: 3rem;
            line-height: 1;
            font-weight: 800;
            letter-spacing: -0.06em;
        }

        .side-badge {
            display: inline-flex;
            margin-top: 12px;
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 0.84rem;
            font-weight: 800;
        }

        .side-foot {
            margin-top: 12px;
            color: var(--subtle);
            font-size: 0.92rem;
            font-weight: 600;
            line-height: 1.45;
        }

        .mini {
            padding: 20px 20px 18px 20px;
            min-height: 128px;
        }

        .mini-label {
            color: var(--muted);
            font-size: 0.9rem;
            font-weight: 700;
            margin-bottom: 14px;
        }

        .mini-value {
            color: var(--text);
            font-size: 2rem;
            line-height: 1;
            font-weight: 800;
            letter-spacing: -0.05em;
        }

        .mini-foot {
            color: var(--subtle);
            font-size: 0.92rem;
            font-weight: 600;
            line-height: 1.5;
            margin-top: 10px;
        }

        .section {
            padding: 24px;
            height: 100%;
        }

        .section-kicker {
            color: var(--muted);
            font-size: 0.76rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .section-title {
            margin: 8px 0 18px 0;
            color: var(--text);
            font-size: 1.38rem;
            font-weight: 800;
            line-height: 1.14;
            letter-spacing: -0.04em;
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
            gap: 12px;
            color: var(--text);
            font-size: 0.98rem;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .mix-track {
            width: 100%;
            height: 10px;
            border-radius: 999px;
            background: rgba(2, 32, 71, 0.06);
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
            padding: 18px;
            border-radius: var(--radius-md);
            background: linear-gradient(180deg, #FFFFFF, #F9FBFC);
            border: 1px solid rgba(2, 32, 71, 0.06);
        }

        .signal-label {
            color: var(--muted);
            font-size: 0.86rem;
            font-weight: 700;
            margin-bottom: 10px;
        }

        .signal-value {
            color: var(--text);
            font-size: 2rem;
            line-height: 1;
            font-weight: 800;
            letter-spacing: -0.05em;
        }

        .list-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 16px 0;
            border-bottom: 1px solid rgba(2, 32, 71, 0.06);
        }

        .list-row:first-child {
            padding-top: 0;
        }

        .list-row:last-child {
            border-bottom: 0;
            padding-bottom: 0;
        }

        .list-main {
            color: var(--text);
            font-size: 1rem;
            font-weight: 800;
            line-height: 1.18;
        }

        .list-sub {
            color: var(--subtle);
            font-size: 0.9rem;
            font-weight: 600;
            margin-top: 6px;
        }

        .list-right {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 66px;
            padding: 8px 11px;
            border-radius: 999px;
            font-size: 0.84rem;
            font-weight: 800;
        }

        .history-wrap {
            margin-top: 18px;
            padding: 24px;
        }

        .history-card {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            padding: 18px 6px;
            border-bottom: 1px solid rgba(2, 32, 71, 0.06);
        }

        .history-card:first-child {
            padding-top: 2px;
        }

        .history-card:last-child {
            border-bottom: 0;
            padding-bottom: 2px;
        }

        .history-left {
            min-width: 0;
        }

        .history-title {
            color: var(--text);
            font-size: 1rem;
            font-weight: 800;
            line-height: 1.18;
        }

        .history-meta {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 8px;
            color: var(--subtle);
            font-size: 0.9rem;
            font-weight: 600;
        }

        .history-right {
            text-align: right;
            flex-shrink: 0;
        }

        .history-risk {
            color: var(--text);
            font-size: 1.4rem;
            font-weight: 800;
            line-height: 1;
            letter-spacing: -0.04em;
        }

        .history-label {
            margin-top: 6px;
            display: inline-flex;
            padding: 7px 11px;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 800;
        }

        .empty-state {
            padding: 70px 30px;
            text-align: center;
        }

        .empty-title {
            color: var(--text);
            font-size: 1.6rem;
            font-weight: 800;
            letter-spacing: -0.04em;
            margin-bottom: 10px;
        }

        .empty-copy {
            color: var(--subtle);
            font-size: 1rem;
            line-height: 1.6;
            font-weight: 600;
        }

        @media (max-width: 1100px) {
            .hero-grid {
                grid-template-columns: 1fr;
            }

            .hero-title {
                font-size: 2.65rem;
            }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def load_data() -> pd.DataFrame:
    rows = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if line:
                    rows.append(json.loads(line))
    return pd.DataFrame(rows)


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
    normalized["status_name"] = normalized["label"].map(lambda x: LABEL_META.get(x, LABEL_META[0])["name"])
    normalized["tone"] = normalized["label"].map(lambda x: LABEL_META.get(x, LABEL_META[0])["tone"])
    normalized["risk_score"] = normalized["label"].map(lambda x: LABEL_META.get(x, LABEL_META[0])["risk"])
    normalized["display_time"] = normalized["timestamp"].map(format_timestamp)
    normalized["confidence_pct"] = (normalized["confidence"] * 100).round(1)
    return normalized


def stat_card(title: str, value: str, foot: str) -> str:
    return f"""
    <div class="card mini">
        <div class="mini-label">{escape(title)}</div>
        <div class="mini-value">{escape(value)}</div>
        <div class="mini-foot">{escape(foot)}</div>
    </div>
    """


def attack_mix_html(df: pd.DataFrame) -> str:
    counts = df["label"].value_counts().to_dict()
    max_count = max(counts.values()) if counts else 1
    order = [5, 3, 4, 2, 1, 0]
    blocks = []
    for label in order:
        meta = LABEL_META[label]
        tone = TONE_META[meta["tone"]]
        count = counts.get(label, 0)
        width = 0 if count == 0 else max(8, int((count / max_count) * 100))
        blocks.append(
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
    return "".join(blocks)


def signal_grid_html(latest: pd.Series) -> str:
    items = []
    for column, label in SIGNAL_ITEMS:
        value = int(latest.get(column, 0) or 0)
        items.append(
            f"""
            <div class="signal-box">
                <div class="signal-label">{escape(label)}</div>
                <div class="signal-value">{value:,}</div>
            </div>
            """
        )
    return "".join(items)


def recent_feed_html(df: pd.DataFrame) -> str:
    rows = []
    for _, row in df.head(5).iterrows():
        tone = TONE_META[row["tone"]]
        rows.append(
            f"""
            <div class="list-row">
                <div>
                    <div class="list-main">{escape(str(row['status_name']))}</div>
                    <div class="list-sub">{escape(str(row['display_time']))} · confidence {row['confidence_pct']:.0f}%</div>
                </div>
                <span class="list-right" style="background:{tone['bg']};color:{tone['fg']};">{int(row['risk_score'])}</span>
            </div>
            """
        )
    return "".join(rows)


def history_html(df: pd.DataFrame) -> str:
    latest_rows = df.iloc[::-1].head(8).copy()
    cards = []
    for _, row in latest_rows.iterrows():
        tone = TONE_META[row["tone"]]
        cards.append(
            f"""
            <div class="history-card">
                <div class="history-left">
                    <div class="history-title">{escape(str(row['status_name']))}</div>
                    <div class="history-meta">
                        <span>{escape(str(row['display_time']))}</span>
                        <span>confidence {row['confidence_pct']:.0f}%</span>
                        <span>패킷 {int(row.get('total_pkt_cnt', 0) or 0):,}</span>
                        <span>TCP {int(row.get('tcp_cnt', 0) or 0):,}</span>
                        <span>UDP {int(row.get('udp_cnt', 0) or 0):,}</span>
                    </div>
                </div>
                <div class="history-right">
                    <div class="history-risk">{int(row['risk_score'])}</div>
                    <span class="history-label" style="background:{tone['bg']};color:{tone['fg']};">{escape(str(row['status_name']))}</span>
                </div>
            </div>
            """
        )

    return f"""
    <div class="card history-wrap">
        <div class="section-kicker">Detection History</div>
        <div class="section-title">최근 탐지 내역</div>
        {''.join(cards)}
    </div>
    """


inject_styles()

placeholder = st.empty()

with placeholder.container():
    df = normalize_data(load_data())

    if df.empty:
        st.markdown(
            """
            <div class="card empty-state">
                <div class="empty-title">라이브 데이터 대기 중</div>
                <div class="empty-copy">Extractor, predictor, monitor가 순서대로 실행되면 이 화면이 실시간 보안 관제 화면으로 바뀝니다.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        latest = df.iloc[-1]
        latest_meta = LABEL_META[int(latest["label"])]
        latest_tone = TONE_META[latest["tone"]]
        attack_count = int((df["label"] != 0).sum())
        attack_ratio = (attack_count / len(df)) * 100 if len(df) else 0
        avg_conf = df["confidence_pct"].replace(0, pd.NA).dropna().mean()
        avg_conf_text = f"{avg_conf:.1f}%" if pd.notna(avg_conf) else "-"

        st.markdown(
            f"""
            <div class="card hero">
                <div class="hero-grid">
                    <div>
                        <span class="hero-kicker">AEGIS · Live Security</span>
                        <div class="hero-title">{escape(latest_meta['name'])}</div>
                        <p class="hero-desc">최근 탐지 {escape(str(latest['display_time']))} · confidence {latest['confidence_pct']:.0f}% · 지금 가장 먼저 봐야 하는 상태와 핵심 수치만 위로 올렸습니다.</p>
                        <div class="chip-row">
                            <span class="chip"><span class="chip-dot"></span>Auto Refresh {REFRESH_SECONDS}s</span>
                            <span class="chip">누적 이벤트 {len(df):,}</span>
                            <span class="chip">공격 비중 {attack_ratio:.0f}%</span>
                        </div>
                    </div>
                    <div class="hero-side">
                        <div class="side-label">현재 리스크</div>
                        <div class="side-value">{int(latest['risk_score'])}</div>
                        <span class="side-badge" style="background:{latest_tone['bg']};color:{latest_tone['fg']};">{escape(latest_meta['name'])}</span>
                        <div class="side-foot">최근 탐지 {escape(str(latest['display_time']))}<br/>Risk Score</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        top_cols = st.columns(4)
        top_cards = [
            stat_card("현재 상태", latest_meta["name"], f"최근 탐지 {latest['display_time']}"),
            stat_card("누적 이벤트", f"{len(df):,}", "관제 파이프라인 총 기록 수"),
            stat_card("공격 비중", f"{attack_ratio:.0f}%", f"정상 제외 {attack_count:,}건"),
            stat_card("평균 신뢰도", avg_conf_text, "confidence 기준 평균"),
        ]
        for column, card in zip(top_cols, top_cards):
            with column:
                st.markdown(card, unsafe_allow_html=True)

        mid_cols = st.columns([1.02, 1.04, 0.94])

        with mid_cols[0]:
            st.markdown(
                f"""
                <div class="card section">
                    <div class="section-kicker">Attack Mix</div>
                    <div class="section-title">유형별 분포</div>
                    {attack_mix_html(df)}
                </div>
                """,
                unsafe_allow_html=True,
            )

        with mid_cols[1]:
            st.markdown(
                f"""
                <div class="card section">
                    <div class="section-kicker">Live Snapshot</div>
                    <div class="section-title">실시간 특징값</div>
                    <div class="signal-grid">
                        {signal_grid_html(latest)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with mid_cols[2]:
            st.markdown(
                f"""
                <div class="card section">
                    <div class="section-kicker">Recent Feed</div>
                    <div class="section-title">최근 이벤트</div>
                    {recent_feed_html(df.iloc[::-1].reset_index(drop=True))}
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown(history_html(df), unsafe_allow_html=True)

time.sleep(REFRESH_SECONDS)
st.rerun()
