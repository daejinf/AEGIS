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
    "safe": {"bg": "#ECFDF3", "fg": "#027A48", "line": "#22C55E"},
    "warn": {"bg": "#FFF7ED", "fg": "#C2410C", "line": "#F97316"},
    "danger": {"bg": "#FEF2F2", "fg": "#B42318", "line": "#EF4444"},
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
            --bg: #f2f4f6;
            --surface: rgba(255, 255, 255, 0.94);
            --surface-strong: #ffffff;
            --line: rgba(2, 32, 71, 0.08);
            --text: #191f28;
            --subtle: #6b7684;
            --muted: #8b95a1;
            --blue: #3182f6;
            --blue-deep: #1b64da;
            --shadow: 0 22px 50px rgba(2, 32, 71, 0.08);
            --radius-xl: 32px;
            --radius-lg: 24px;
            --radius-md: 18px;
        }

        .stApp {
            background:
                radial-gradient(circle at top right, rgba(49, 130, 246, 0.10), transparent 24%),
                linear-gradient(180deg, #f8fbff 0%, var(--bg) 55%, #eef2f7 100%);
            color: var(--text);
        }

        html, body, [class*="css"] {
            font-family: "Pretendard", "SF Pro Display", "Segoe UI", sans-serif;
            color: var(--text);
        }

        .block-container {
            max-width: 1360px;
            padding-top: 1.6rem;
            padding-bottom: 2.6rem;
        }

        [data-testid="stHeader"] {
            background: transparent;
        }

        .surface-card {
            background: var(--surface);
            border: 1px solid var(--line);
            box-shadow: var(--shadow);
            border-radius: var(--radius-xl);
        }

        .hero-card {
            padding: 30px 32px;
            margin-bottom: 18px;
        }

        .hero-grid {
            display: grid;
            grid-template-columns: minmax(0, 1.2fr) 240px;
            gap: 22px;
            align-items: center;
        }

        .eyebrow {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 9px 13px;
            border-radius: 999px;
            background: #e8f3ff;
            color: var(--blue-deep);
            font-size: 0.78rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .hero-title {
            margin: 16px 0 8px 0;
            font-size: 3.25rem;
            line-height: 0.98;
            letter-spacing: -0.07em;
            font-weight: 800;
        }

        .hero-copy {
            margin: 0;
            color: var(--subtle);
            font-size: 1rem;
            line-height: 1.6;
            font-weight: 600;
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
            background: var(--surface-strong);
            border: 1px solid rgba(2, 32, 71, 0.06);
            font-size: 0.92rem;
            font-weight: 700;
            color: var(--text);
        }

        .chip-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--blue);
        }

        .status-panel {
            padding: 20px 22px;
            border-radius: 26px;
            background: linear-gradient(180deg, #ffffff, #f8fbff);
            border: 1px solid rgba(2, 32, 71, 0.06);
        }

        .status-label {
            font-size: 0.84rem;
            color: var(--muted);
            font-weight: 700;
            margin-bottom: 10px;
        }

        .status-value {
            font-size: 3rem;
            line-height: 1;
            font-weight: 800;
            letter-spacing: -0.06em;
            color: var(--text);
        }

        .status-badge {
            display: inline-flex;
            margin-top: 12px;
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 0.84rem;
            font-weight: 800;
        }

        .status-foot {
            margin-top: 12px;
            font-size: 0.92rem;
            color: var(--subtle);
            font-weight: 600;
            line-height: 1.45;
        }

        .mini-card {
            padding: 20px 20px 18px 20px;
            min-height: 132px;
        }

        .mini-label {
            color: var(--muted);
            font-size: 0.9rem;
            font-weight: 700;
            margin-bottom: 16px;
        }

        .mini-value {
            color: var(--text);
            font-size: 2.1rem;
            line-height: 1;
            font-weight: 800;
            letter-spacing: -0.05em;
        }

        .mini-foot {
            margin-top: 10px;
            color: var(--subtle);
            font-size: 0.93rem;
            line-height: 1.55;
            font-weight: 600;
        }

        .body-card {
            padding: 24px;
            height: 100%;
        }

        .section-label {
            color: var(--muted);
            font-size: 0.78rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .section-title {
            margin: 8px 0 18px 0;
            color: var(--text);
            font-size: 1.4rem;
            font-weight: 800;
            line-height: 1.12;
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
            margin-bottom: 8px;
            font-size: 0.98rem;
            font-weight: 700;
            color: var(--text);
        }

        .mix-track {
            width: 100%;
            height: 10px;
            border-radius: 999px;
            overflow: hidden;
            background: rgba(2, 32, 71, 0.06);
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
            border-radius: 18px;
            background: linear-gradient(180deg, #ffffff, #f8fafc);
            border: 1px solid rgba(2, 32, 71, 0.06);
        }

        .signal-name {
            color: var(--muted);
            font-size: 0.86rem;
            font-weight: 700;
            margin-bottom: 10px;
        }

        .signal-value {
            color: var(--text);
            font-size: 2rem;
            font-weight: 800;
            line-height: 1;
            letter-spacing: -0.05em;
        }

        .feed-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 14px 0;
            border-bottom: 1px solid rgba(2, 32, 71, 0.06);
        }

        .feed-item:first-child {
            padding-top: 0;
        }

        .feed-item:last-child {
            padding-bottom: 0;
            border-bottom: 0;
        }

        .feed-name {
            color: var(--text);
            font-size: 1rem;
            font-weight: 800;
            line-height: 1.18;
        }

        .feed-meta {
            margin-top: 6px;
            color: var(--subtle);
            font-size: 0.9rem;
            font-weight: 600;
        }

        .feed-risk {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 64px;
            padding: 8px 10px;
            border-radius: 999px;
            font-size: 0.84rem;
            font-weight: 800;
        }

        .ledger-wrap {
            margin-top: 18px;
            padding: 24px;
        }

        .ledger-head,
        .ledger-row {
            display: grid;
            grid-template-columns: 120px 150px 110px 100px 100px 90px 90px 90px 90px 90px;
            gap: 0;
            align-items: center;
        }

        .ledger-head {
            padding: 0 8px 14px 8px;
            color: var(--muted);
            font-size: 0.78rem;
            font-weight: 800;
            letter-spacing: 0.06em;
            text-transform: uppercase;
        }

        .ledger-row {
            padding: 16px 8px;
            border-top: 1px solid rgba(2, 32, 71, 0.06);
            font-size: 0.94rem;
            font-weight: 700;
            color: var(--text);
        }

        .ledger-badge {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: fit-content;
            padding: 7px 11px;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 800;
        }

        .ledger-scroll {
            overflow-x: auto;
            overflow-y: hidden;
            border-radius: 20px;
            background: rgba(255, 255, 255, 0.78);
            border: 1px solid rgba(2, 32, 71, 0.05);
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
                font-size: 2.7rem;
            }

            .ledger-head,
            .ledger-row {
                min-width: 1020px;
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
    normalized["status_name"] = normalized["label"].map(lambda value: LABEL_META.get(value, LABEL_META[0])["name"])
    normalized["tone"] = normalized["label"].map(lambda value: LABEL_META.get(value, LABEL_META[0])["tone"])
    normalized["risk_score"] = normalized["label"].map(lambda value: LABEL_META.get(value, LABEL_META[0])["risk"])
    normalized["display_time"] = normalized["timestamp"].map(format_timestamp)
    normalized["confidence_pct"] = (normalized["confidence"] * 100).round(1)
    return normalized


def stat_card(title: str, value: str, foot: str) -> str:
    return f"""
    <div class="surface-card mini-card">
        <div class="mini-label">{escape(title)}</div>
        <div class="mini-value">{escape(value)}</div>
        <div class="mini-foot">{escape(foot)}</div>
    </div>
    """


def attack_mix_html(df: pd.DataFrame) -> str:
    counts = df["label"].value_counts().to_dict()
    max_count = max(counts.values()) if counts else 1
    order = [1, 3, 4, 2, 5, 0]
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
                <div class="signal-name">{escape(label)}</div>
                <div class="signal-value">{value:,}</div>
            </div>
            """
        )
    return "".join(items)


def recent_feed_html(df: pd.DataFrame) -> str:
    rows = []
    for _, row in df.head(6).iterrows():
        tone = TONE_META[row["tone"]]
        confidence = f"{row['confidence_pct']:.0f}%"
        rows.append(
            f"""
            <div class="feed-item">
                <div>
                    <div class="feed-name">{escape(str(row['status_name']))}</div>
                    <div class="feed-meta">{escape(str(row['display_time']))} · confidence {confidence}</div>
                </div>
                <span class="feed-risk" style="background:{tone['bg']};color:{tone['fg']};">{int(row['risk_score'])}</span>
            </div>
            """
        )
    return "".join(rows)


def ledger_html(df: pd.DataFrame) -> str:
    latest_rows = df.iloc[::-1].head(10).copy()
    body = []
    for _, row in latest_rows.iterrows():
        tone = TONE_META[row["tone"]]
        body.append(
            f"""
            <div class="ledger-row">
                <div>{escape(str(row['display_time']))}</div>
                <div><span class="ledger-badge" style="background:{tone['bg']};color:{tone['fg']};">{escape(str(row['status_name']))}</span></div>
                <div>{row['confidence_pct']:.0f}%</div>
                <div>{int(row['risk_score'])}</div>
                <div>{int(row.get('total_pkt_cnt', 0) or 0):,}</div>
                <div>{int(row.get('tcp_cnt', 0) or 0):,}</div>
                <div>{int(row.get('udp_cnt', 0) or 0):,}</div>
                <div>{int(row.get('icmp_cnt', 0) or 0):,}</div>
                <div>{int(row.get('dns_query_cnt', 0) or 0):,}</div>
                <div>{int(row.get('failed_login_cnt', 0) or 0):,}</div>
            </div>
            """
        )

    return f"""
    <div class="surface-card ledger-wrap">
        <div class="section-label">Event Log</div>
        <div class="section-title">최근 이벤트 로그</div>
        <div class="ledger-scroll">
            <div class="ledger-head">
                <div>시간</div>
                <div>유형</div>
                <div>신뢰도</div>
                <div>리스크</div>
                <div>패킷</div>
                <div>TCP</div>
                <div>UDP</div>
                <div>ICMP</div>
                <div>DNS</div>
                <div>SSH</div>
            </div>
            {''.join(body)}
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
            <div class="surface-card empty-state">
                <div class="empty-title">라이브 데이터 대기 중</div>
                <div class="empty-copy">Extractor, predictor, monitor가 순서대로 실행되면 이 화면이 실시간 관제 대시보드로 채워집니다.</div>
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
        avg_confidence = df["confidence_pct"].replace(0, pd.NA).dropna().mean()
        avg_confidence_text = f"{avg_confidence:.1f}%" if pd.notna(avg_confidence) else "-"

        st.markdown(
            f"""
            <div class="surface-card hero-card">
                <div class="hero-grid">
                    <div>
                        <span class="eyebrow">AEGIS · Live Security</span>
                        <div class="hero-title">{escape(latest_meta['name'])}</div>
                        <p class="hero-copy">최근 탐지 {escape(str(latest['display_time']))} · confidence {latest['confidence_pct']:.0f}% · 실시간 패킷과 예측 결과를 가장 먼저 읽히는 순서로 정리했습니다.</p>
                        <div class="chip-row">
                            <span class="chip"><span class="chip-dot"></span>Auto Refresh {REFRESH_SECONDS}s</span>
                            <span class="chip">누적 이벤트 {len(df):,}</span>
                            <span class="chip">공격 비중 {attack_ratio:.0f}%</span>
                        </div>
                    </div>
                    <div class="status-panel">
                        <div class="status-label">현재 상태</div>
                        <div class="status-value">{int(latest['risk_score'])}</div>
                        <span class="status-badge" style="background:{latest_tone['bg']};color:{latest_tone['fg']};">{escape(latest_meta['name'])}</span>
                        <div class="status-foot">Risk Score<br/>최근 탐지 {escape(str(latest['display_time']))}</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        summary_cols = st.columns(4)
        summary_cards = [
            stat_card("현재 상태", latest_meta["name"], f"최근 탐지 {latest['display_time']}"),
            stat_card("누적 이벤트", f"{len(df):,}", "관제 파이프라인 총 기록 수"),
            stat_card("공격 비중", f"{attack_ratio:.0f}%", f"정상 제외 {attack_count:,}건"),
            stat_card("평균 신뢰도", avg_confidence_text, "confidence 기준 평균"),
        ]
        for column, card in zip(summary_cols, summary_cards):
            with column:
                st.markdown(card, unsafe_allow_html=True)

        body_cols = st.columns([1.05, 1.05, 0.9])

        with body_cols[0]:
            st.markdown(
                f"""
                <div class="surface-card body-card">
                    <div class="section-label">Attack Mix</div>
                    <div class="section-title">유형별 분포</div>
                    {attack_mix_html(df)}
                </div>
                """,
                unsafe_allow_html=True,
            )

        with body_cols[1]:
            st.markdown(
                f"""
                <div class="surface-card body-card">
                    <div class="section-label">Latest Snapshot</div>
                    <div class="section-title">실시간 특징값</div>
                    <div class="signal-grid">
                        {signal_grid_html(latest)}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        with body_cols[2]:
            st.markdown(
                f"""
                <div class="surface-card body-card">
                    <div class="section-label">Recent Feed</div>
                    <div class="section-title">최근 이벤트</div>
                    {recent_feed_html(df.iloc[::-1].reset_index(drop=True))}
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown(ledger_html(df), unsafe_allow_html=True)

time.sleep(REFRESH_SECONDS)
st.rerun()
