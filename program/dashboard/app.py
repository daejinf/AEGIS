import json
import os
import time
from datetime import datetime

import pandas as pd
import streamlit as st


LOG_FILE = "live_dashboard.json"
REFRESH_SECONDS = 2

LABEL_META = {
    0: {"name": "Normal", "badge": "정상", "tone": "safe", "risk": 8},
    1: {"name": "ICMP Flood", "badge": "ICMP Flood", "tone": "danger", "risk": 90},
    2: {"name": "Port Scan", "badge": "Port Scan", "tone": "warn", "risk": 72},
    3: {"name": "SSH Brute Force", "badge": "SSH Brute Force", "tone": "danger", "risk": 84},
    4: {"name": "ARP Spoofing", "badge": "ARP Spoofing", "tone": "danger", "risk": 88},
    5: {"name": "DNS Anomaly", "badge": "DNS Anomaly", "tone": "warn", "risk": 68},
}

TONE_COLORS = {
    "safe": {"bg": "#ECFDF3", "fg": "#027A48", "chip": "#D1FADF"},
    "warn": {"bg": "#FFFAEB", "fg": "#B54708", "chip": "#FEE4A6"},
    "danger": {"bg": "#FEF3F2", "fg": "#B42318", "chip": "#FECDCA"},
}


st.set_page_config(
    page_title="AEGIS Security Center",
    page_icon="🛡️",
    layout="wide",
)


def inject_styles() -> None:
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Pretendard:wght@400;500;600;700;800&display=swap');

        :root {
            --bg: #f5f7fb;
            --surface: rgba(255, 255, 255, 0.86);
            --surface-strong: #ffffff;
            --stroke: rgba(15, 23, 42, 0.08);
            --text: #0f172a;
            --muted: #667085;
            --blue: #1677ff;
            --blue-soft: #e8f1ff;
            --shadow: 0 18px 48px rgba(15, 23, 42, 0.08);
            --radius-xl: 30px;
            --radius-lg: 24px;
            --radius-md: 18px;
        }

        .stApp {
            background:
                radial-gradient(circle at top left, rgba(22, 119, 255, 0.10), transparent 26%),
                radial-gradient(circle at top right, rgba(125, 211, 252, 0.18), transparent 24%),
                linear-gradient(180deg, #fbfcff 0%, var(--bg) 54%, #eef3fb 100%);
        }

        html, body, [class*="css"] {
            font-family: "Pretendard", "SF Pro Display", "Segoe UI", sans-serif;
            color: var(--text);
        }

        .block-container {
            padding-top: 2.2rem;
            padding-bottom: 2.5rem;
            max-width: 1380px;
        }

        [data-testid="stHeader"] {
            background: rgba(255, 255, 255, 0);
        }

        [data-testid="stMetric"] {
            background: transparent;
        }

        div[data-testid="stMetric"] {
            padding: 0 !important;
        }

        [data-testid="stDataFrame"] {
            border-radius: 22px;
            overflow: hidden;
            border: 1px solid var(--stroke);
            box-shadow: var(--shadow);
            background: var(--surface-strong);
        }

        .hero-card, .surface-card {
            background: var(--surface);
            backdrop-filter: blur(22px);
            border: 1px solid var(--stroke);
            box-shadow: var(--shadow);
            border-radius: var(--radius-xl);
        }

        .hero-card {
            padding: 32px 34px;
            margin-bottom: 20px;
            position: relative;
            overflow: hidden;
        }

        .hero-card::after {
            content: "";
            position: absolute;
            inset: auto -80px -80px auto;
            width: 260px;
            height: 260px;
            border-radius: 999px;
            background: radial-gradient(circle, rgba(22, 119, 255, 0.18), rgba(22, 119, 255, 0));
        }

        .surface-card {
            padding: 24px 24px 22px 24px;
            height: 100%;
        }

        .eyebrow {
            color: var(--blue);
            font-size: 0.82rem;
            font-weight: 700;
            letter-spacing: 0.06em;
            text-transform: uppercase;
            margin-bottom: 12px;
        }

        .hero-title {
            font-size: 2.35rem;
            line-height: 1.1;
            font-weight: 800;
            letter-spacing: -0.04em;
            margin: 0;
            color: var(--text);
        }

        .hero-copy {
            margin-top: 12px;
            max-width: 760px;
            color: var(--muted);
            font-size: 1.02rem;
            line-height: 1.72;
        }

        .hero-meta-row {
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
            margin-top: 22px;
        }

        .chip {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 14px;
            border-radius: 999px;
            font-size: 0.92rem;
            font-weight: 600;
            border: 1px solid rgba(15, 23, 42, 0.05);
            background: #ffffff;
            color: #101828;
        }

        .chip .dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--blue);
        }

        .metric-card {
            background: rgba(255, 255, 255, 0.84);
            border: 1px solid var(--stroke);
            box-shadow: var(--shadow);
            border-radius: var(--radius-lg);
            padding: 22px 22px 18px 22px;
            min-height: 146px;
        }

        .metric-label {
            color: var(--muted);
            font-size: 0.92rem;
            font-weight: 600;
            margin-bottom: 18px;
        }

        .metric-value {
            font-size: 2rem;
            font-weight: 800;
            letter-spacing: -0.04em;
            color: var(--text);
            line-height: 1.05;
        }

        .metric-sub {
            margin-top: 12px;
            color: var(--muted);
            font-size: 0.95rem;
            line-height: 1.55;
        }

        .section-title {
            font-size: 1.15rem;
            font-weight: 750;
            letter-spacing: -0.02em;
            color: var(--text);
            margin-bottom: 8px;
        }

        .section-copy {
            color: var(--muted);
            font-size: 0.95rem;
            line-height: 1.6;
            margin-bottom: 18px;
        }

        .event-item {
            padding: 16px 0;
            border-bottom: 1px solid rgba(15, 23, 42, 0.06);
        }

        .event-item:last-child {
            border-bottom: 0;
            padding-bottom: 2px;
        }

        .event-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            margin-bottom: 8px;
        }

        .event-name {
            font-weight: 700;
            color: var(--text);
            font-size: 0.98rem;
        }

        .event-meta {
            color: var(--muted);
            font-size: 0.9rem;
            line-height: 1.6;
        }

        .pill {
            display: inline-flex;
            align-items: center;
            padding: 7px 11px;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 700;
            letter-spacing: -0.01em;
            white-space: nowrap;
        }

        .empty-state {
            padding: 64px 30px;
            text-align: center;
            border-radius: var(--radius-xl);
            background: rgba(255, 255, 255, 0.82);
            border: 1px dashed rgba(15, 23, 42, 0.14);
            color: var(--muted);
            box-shadow: var(--shadow);
        }

        .empty-state h3 {
            margin: 0 0 12px 0;
            color: var(--text);
            font-size: 1.4rem;
            letter-spacing: -0.03em;
        }

        .stTabs [data-baseweb="tab-list"] {
            gap: 8px;
            background: rgba(255, 255, 255, 0.70);
            border-radius: 16px;
            padding: 6px;
            border: 1px solid var(--stroke);
        }

        .stTabs [data-baseweb="tab"] {
            height: 44px;
            border-radius: 12px;
            padding: 0 18px;
            font-weight: 700;
        }

        .stTabs [aria-selected="true"] {
            background: white !important;
            box-shadow: 0 8px 24px rgba(15, 23, 42, 0.08);
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
        "syn_cnt",
        "ack_cnt",
        "unique_dst_port_cnt",
        "unique_src_ip_cnt",
        "dns_query_cnt",
        "gratuitous_arp_cnt",
        "failed_login_cnt",
        "mac_change_cnt",
    ]
    for column in numeric_columns:
        if column in normalized.columns:
            normalized[column] = pd.to_numeric(normalized[column], errors="coerce")

    if "label" not in normalized.columns:
        normalized["label"] = 0

    normalized["label"] = normalized["label"].fillna(0).astype(int)
    normalized["confidence"] = normalized.get("confidence", pd.Series([None] * len(normalized))).fillna(0)
    normalized["label_name"] = normalized["label"].map(
        lambda value: LABEL_META.get(value, LABEL_META[0])["name"]
    )
    normalized["badge_name"] = normalized["label"].map(
        lambda value: LABEL_META.get(value, LABEL_META[0])["badge"]
    )
    normalized["risk_score"] = normalized["label"].map(
        lambda value: LABEL_META.get(value, LABEL_META[0])["risk"]
    )
    normalized["tone"] = normalized["label"].map(
        lambda value: LABEL_META.get(value, LABEL_META[0])["tone"]
    )
    normalized["display_time"] = normalized["timestamp"].map(format_timestamp)
    normalized["confidence_pct"] = (normalized["confidence"] * 100).round(1)
    return normalized


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


def render_metric_card(title: str, value: str, subtext: str) -> None:
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{title}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-sub">{subtext}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_badge(label: int) -> str:
    meta = LABEL_META.get(label, LABEL_META[0])
    colors = TONE_COLORS[meta["tone"]]
    return (
        f"<span class='pill' style='background:{colors['bg']};color:{colors['fg']};"
        f"border:1px solid {colors['chip']};'>{meta['badge']}</span>"
    )


def render_event_feed(df: pd.DataFrame) -> None:
    st.markdown('<div class="section-title">Recent Security Events</div>', unsafe_allow_html=True)
    st.markdown(
        '<div class="section-copy">가장 최근에 기록된 탐지 결과를 빠르게 훑어보고, 어떤 공격이 우세한지 즉시 파악할 수 있도록 구성했습니다.</div>',
        unsafe_allow_html=True,
    )

    for _, row in df.head(8).iterrows():
        confidence_text = f"{row['confidence_pct']:.1f}%" if row["confidence"] else "N/A"
        st.markdown(
            f"""
            <div class="event-item">
                <div class="event-top">
                    <div class="event-name">{row['label_name']}</div>
                    {render_badge(int(row['label']))}
                </div>
                <div class="event-meta">
                    Time {row['display_time']}<br/>
                    Confidence {confidence_text} · Risk Score {int(row['risk_score'])}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def build_display_table(df: pd.DataFrame) -> pd.DataFrame:
    table = df.copy()
    table["상태"] = table["badge_name"]
    table["시간"] = table["display_time"]
    table["신뢰도(%)"] = table["confidence_pct"]
    table["위험도"] = table["risk_score"]

    column_map = {
        "total_pkt_cnt": "전체 패킷",
        "tcp_cnt": "TCP",
        "udp_cnt": "UDP",
        "icmp_cnt": "ICMP",
        "failed_login_cnt": "SSH 실패",
        "dns_query_cnt": "DNS 질의",
        "unique_dst_port_cnt": "대상 포트 수",
        "unique_src_ip_cnt": "출발지 IP 수",
    }
    for original, renamed in column_map.items():
        if original in table.columns:
            table[renamed] = table[original]

    preferred_columns = [
        "시간",
        "상태",
        "신뢰도(%)",
        "위험도",
        "전체 패킷",
        "TCP",
        "UDP",
        "ICMP",
        "SSH 실패",
        "DNS 질의",
        "대상 포트 수",
        "출발지 IP 수",
    ]
    available_columns = [column for column in preferred_columns if column in table.columns]
    return table[available_columns].head(12)


inject_styles()

placeholder = st.empty()

with placeholder.container():
    raw_df = load_data()
    df = normalize_data(raw_df)

    if df.empty:
        st.markdown(
            """
            <div class="empty-state">
                <h3>AEGIS is waiting for live traffic</h3>
                <p>Extractor, predictor, monitor가 순서대로 실행되면 이 화면이 실시간 보안 관제 센터로 바뀝니다.</p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        latest = df.iloc[-1]
        attack_count = int((df["label"] != 0).sum())
        attack_ratio = (attack_count / len(df)) * 100 if len(df) else 0
        average_confidence = df["confidence_pct"].replace(0, pd.NA).dropna().mean()
        average_confidence_text = f"{average_confidence:.1f}%" if pd.notna(average_confidence) else "N/A"
        latest_badge = render_badge(int(latest["label"]))

        st.markdown(
            f"""
            <div class="hero-card">
                <div class="eyebrow">AEGIS Security Center</div>
                <h1 class="hero-title">네트워크 공격 흐름을<br/>한 화면에서 부드럽고 선명하게</h1>
                <div class="hero-copy">
                    실시간 패킷 특징값, AI 예측 결과, 위험 흐름을 하나의 관제 표면으로 정리했습니다.
                    과하게 장식하지 않고, 중요한 신호만 빠르게 읽히도록 톤을 정교하게 맞췄습니다.
                </div>
                <div class="hero-meta-row">
                    <span class="chip"><span class="dot"></span>Auto Refresh {REFRESH_SECONDS}s</span>
                    <span class="chip">Latest {latest['display_time']}</span>
                    <span class="chip">Current Status {LABEL_META.get(int(latest['label']), LABEL_META[0])['name']}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        metric_cols = st.columns(4)
        with metric_cols[0]:
            render_metric_card(
                "총 누적 이벤트",
                f"{len(df):,}",
                "현재까지 관제 파이프라인에 기록된 전체 이벤트 수",
            )
        with metric_cols[1]:
            render_metric_card(
                "실시간 상태",
                LABEL_META.get(int(latest["label"]), LABEL_META[0])["badge"],
                f"최근 감지 시각 {latest['display_time']}",
            )
        with metric_cols[2]:
            render_metric_card(
                "공격 비중",
                f"{attack_ratio:.0f}%",
                f"정상 제외 {attack_count:,}건이 공격 또는 이상 이벤트",
            )
        with metric_cols[3]:
            render_metric_card(
                "평균 신뢰도",
                average_confidence_text,
                "모델 confidence가 있는 이벤트 기준 평균값",
            )

        st.write("")

        overview_col, feed_col = st.columns([1.35, 0.85])

        with overview_col:
            st.markdown('<div class="surface-card">', unsafe_allow_html=True)
            st.markdown('<div class="section-title">Live Overview</div>', unsafe_allow_html=True)
            st.markdown(
                '<div class="section-copy">최근 30개 이벤트의 위험 흐름과 공격 유형 분포를 같이 보여줘서, 순간 스파이크와 반복 패턴을 동시에 읽을 수 있습니다.</div>',
                unsafe_allow_html=True,
            )

            risk_trend = df[["display_time", "risk_score"]].tail(30).set_index("display_time")
            st.line_chart(risk_trend, height=260, color="#1677FF")

            distribution = (
                df["badge_name"]
                .value_counts()
                .rename_axis("attack")
                .reset_index(name="count")
                .set_index("attack")
            )
            st.bar_chart(distribution, height=220, color="#3B82F6")
            st.markdown("</div>", unsafe_allow_html=True)

        with feed_col:
            st.markdown('<div class="surface-card">', unsafe_allow_html=True)
            render_event_feed(df.iloc[::-1].reset_index(drop=True))
            st.markdown("</div>", unsafe_allow_html=True)

        st.write("")

        tabs = st.tabs(["Event Table", "Traffic Snapshot"])

        with tabs[0]:
            st.markdown('<div class="surface-card">', unsafe_allow_html=True)
            st.markdown('<div class="section-title">Detailed Event Table</div>', unsafe_allow_html=True)
            st.markdown(
                '<div class="section-copy">최근 이벤트를 실무적으로 바로 읽을 수 있게 컬럼을 정리했습니다. 숫자는 빠르게 비교되고, 상태는 배지로 구분됩니다.</div>',
                unsafe_allow_html=True,
            )
            display_table = build_display_table(df.iloc[::-1].reset_index(drop=True))
            st.dataframe(display_table, use_container_width=True, hide_index=True)
            st.markdown("</div>", unsafe_allow_html=True)

        with tabs[1]:
            st.markdown('<div class="surface-card">', unsafe_allow_html=True)
            st.markdown('<div class="section-title">Latest Traffic Snapshot</div>', unsafe_allow_html=True)
            st.markdown(
                '<div class="section-copy">가장 최근 이벤트의 네트워크 특징값을 카드형으로 보여줘서, 지금 어떤 신호가 커졌는지 바로 읽히게 만들었습니다.</div>',
                unsafe_allow_html=True,
            )
            snapshot_cols = st.columns(4)
            snapshot_pairs = [
                ("전체 패킷", int(latest.get("total_pkt_cnt", 0))),
                ("TCP", int(latest.get("tcp_cnt", 0))),
                ("UDP", int(latest.get("udp_cnt", 0))),
                ("ICMP", int(latest.get("icmp_cnt", 0))),
                ("DNS 질의", int(latest.get("dns_query_cnt", 0))),
                ("SSH 실패", int(latest.get("failed_login_cnt", 0))),
                ("대상 포트 수", int(latest.get("unique_dst_port_cnt", 0))),
                ("출발지 IP 수", int(latest.get("unique_src_ip_cnt", 0))),
            ]
            for column, (title, value) in zip(snapshot_cols * 2, snapshot_pairs):
                with column:
                    render_metric_card(title, f"{value:,}", "latest event snapshot")
            st.markdown("</div>", unsafe_allow_html=True)

time.sleep(REFRESH_SECONDS)
st.rerun()
