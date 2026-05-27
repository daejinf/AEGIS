import json
import os
import time
from datetime import datetime
from html import escape
from textwrap import dedent

import pandas as pd
import streamlit as st


LOG_FILE = "live_dashboard.json"
REFRESH_SECONDS = 2
MAX_HISTORY_ROWS = 50

LABEL_META = {
    0: {
        "name": "정상",
        "tone": "safe",
        "risk": 8,
        "summary": "정상 흐름입니다. 핵심 수치만 유지하면서 상태를 관찰합니다.",
    },
    1: {
        "name": "ICMP Flood",
        "tone": "danger",
        "risk": 92,
        "summary": "짧은 시간에 ICMP 패킷이 급격히 늘어난 흐름입니다.",
    },
    2: {
        "name": "Port Scan",
        "tone": "warn",
        "risk": 74,
        "summary": "대상 포트 탐색 패턴이 다수의 요청으로 관찰됩니다.",
    },
    3: {
        "name": "SSH Brute Force",
        "tone": "danger",
        "risk": 86,
        "summary": "SSH 로그인 실패가 반복되는 계정 추측 흐름입니다.",
    },
    4: {
        "name": "ARP Spoofing",
        "tone": "danger",
        "risk": 90,
        "summary": "ARP 테이블을 교란할 가능성이 높은 네트워크 흐름입니다.",
    },
    5: {
        "name": "DNS Anomaly",
        "tone": "warn",
        "risk": 68,
        "summary": "평소보다 비정상적인 DNS 질의 패턴이 감지되었습니다.",
    },
}

TONE_META = {
    "safe": {
        "accent": "#2E8B57",
        "soft": "#EAF8EF",
        "border": "#D9F0E2",
        "text": "#157347",
    },
    "warn": {
        "accent": "#F97316",
        "soft": "#FFF3E8",
        "border": "#FDD8B5",
        "text": "#C2410C",
    },
    "danger": {
        "accent": "#E5484D",
        "soft": "#FFF0F1",
        "border": "#FFD0D2",
        "text": "#C0262D",
    },
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


def render_html(html: str) -> None:
    st.markdown(dedent(html).strip(), unsafe_allow_html=True)


def inject_styles() -> None:
    render_html(
        """
        <style>
        :root {
            --bg: #f2f4f6;
            --surface: rgba(255, 255, 255, 0.94);
            --surface-strong: rgba(255, 255, 255, 0.98);
            --line: rgba(15, 23, 42, 0.08);
            --text: #191f28;
            --sub: #4e5968;
            --muted: #8b95a1;
            --blue: #3182f6;
            --blue-soft: #eaf2ff;
            --shadow: 0 18px 48px rgba(15, 23, 42, 0.06);
            --radius-xl: 30px;
            --radius-lg: 22px;
            --radius-md: 16px;
        }

        .stApp {
            background:
                radial-gradient(circle at top left, rgba(49, 130, 246, 0.08), transparent 22%),
                linear-gradient(180deg, #f8fbff 0%, #f2f4f6 60%, #eef2f7 100%);
        }

        html, body, [class*="css"] {
            font-family: "Pretendard Variable", "Pretendard", "Inter", "Noto Sans KR", "SF Pro Display", "Segoe UI", sans-serif;
            color: var(--text);
        }

        [data-testid="stHeader"] {
            background: transparent;
        }

        .block-container {
            max-width: 1260px;
            padding-top: 1.3rem;
            padding-bottom: 2.6rem;
        }

        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            padding: 2px 4px 8px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .brand-mark {
            width: 38px;
            height: 38px;
            border-radius: 14px;
            background: linear-gradient(180deg, #4f9bff 0%, #1f6feb 100%);
            color: #fff;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            font-size: 0.98rem;
            font-weight: 800;
            letter-spacing: -0.02em;
            box-shadow: 0 10px 22px rgba(49, 130, 246, 0.24);
        }

        .brand-title {
            font-size: 1.08rem;
            font-weight: 800;
            letter-spacing: -0.03em;
        }

        .brand-sub {
            color: var(--muted);
            font-size: 0.86rem;
            font-weight: 600;
            margin-top: 2px;
        }

        .topbar-meta {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            justify-content: flex-end;
        }

        .meta-chip, .hero-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 14px;
            border-radius: 999px;
            background: rgba(255, 255, 255, 0.88);
            border: 1px solid rgba(15, 23, 42, 0.06);
            color: var(--text);
            font-size: 0.9rem;
            font-weight: 700;
        }

        .meta-dot {
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: var(--blue);
        }

        .shell {
            background: var(--surface);
            border: 1px solid var(--line);
            box-shadow: var(--shadow);
            backdrop-filter: blur(10px);
        }

        .hero {
            border-radius: var(--radius-xl);
            padding: 28px 30px;
            display: grid;
            grid-template-columns: minmax(0, 1fr) 290px;
            gap: 22px;
            margin-bottom: 16px;
        }

        .hero-kicker {
            display: inline-flex;
            align-items: center;
            padding: 8px 13px;
            border-radius: 999px;
            background: var(--blue-soft);
            color: var(--blue);
            font-size: 0.76rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .hero-title {
            margin: 18px 0 10px;
            font-size: 3.8rem;
            line-height: 0.96;
            letter-spacing: -0.09em;
            font-weight: 800;
        }

        .hero-summary {
            color: var(--sub);
            font-size: 1.02rem;
            line-height: 1.6;
            font-weight: 600;
            margin: 0;
        }

        .hero-strip {
            margin-top: 18px;
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }

        .hero-side {
            border-radius: 24px;
            padding: 22px;
            background: linear-gradient(180deg, #ffffff 0%, #f8fbff 100%);
            border: 1px solid rgba(15, 23, 42, 0.06);
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        .hero-side-label {
            color: var(--muted);
            font-size: 0.82rem;
            font-weight: 700;
        }

        .hero-side-score {
            margin-top: 8px;
            font-size: 3.4rem;
            line-height: 1;
            letter-spacing: -0.08em;
            font-weight: 800;
        }

        .hero-side-badge, .tone-pill {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: fit-content;
            min-width: 88px;
            margin-top: 12px;
            padding: 8px 12px;
            border-radius: 999px;
            font-size: 0.84rem;
            font-weight: 800;
            border: 1px solid transparent;
        }

        .hero-side-meta {
            margin-top: 14px;
            color: var(--sub);
            font-size: 0.92rem;
            line-height: 1.5;
            font-weight: 600;
        }

        .overview {
            border-radius: var(--radius-lg);
            padding: 8px 4px;
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 0;
            margin-bottom: 16px;
        }

        .overview-item {
            padding: 16px 22px;
            position: relative;
        }

        .overview-item:not(:last-child)::after {
            content: "";
            position: absolute;
            top: 18px;
            right: 0;
            width: 1px;
            height: calc(100% - 36px);
            background: rgba(15, 23, 42, 0.08);
        }

        .overview-label {
            color: var(--muted);
            font-size: 0.84rem;
            font-weight: 700;
            margin-bottom: 12px;
        }

        .overview-value {
            font-size: 2.1rem;
            line-height: 1;
            letter-spacing: -0.06em;
            font-weight: 800;
            color: var(--text);
        }

        .overview-foot {
            margin-top: 10px;
            color: var(--sub);
            font-size: 0.92rem;
            line-height: 1.5;
            font-weight: 600;
        }

        .section-head {
            border-radius: var(--radius-lg);
            padding: 22px 24px;
            margin-bottom: 12px;
        }

        .section-kicker {
            color: var(--muted);
            font-size: 0.76rem;
            font-weight: 800;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .section-title {
            margin: 8px 0 0;
            font-size: 1.82rem;
            line-height: 1.08;
            letter-spacing: -0.06em;
            font-weight: 800;
            color: var(--text);
        }

        .section-copy {
            margin-top: 10px;
            color: var(--sub);
            font-size: 0.95rem;
            line-height: 1.6;
            font-weight: 600;
        }

        .detail-card {
            margin-top: 14px;
            padding: 22px;
            border-radius: 22px;
            background: linear-gradient(180deg, rgba(255, 255, 255, 0.98), rgba(248, 251, 255, 0.96));
            border: 1px solid rgba(15, 23, 42, 0.08);
            box-shadow: 0 12px 28px rgba(15, 23, 42, 0.05);
        }

        .detail-top {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 18px;
        }

        .detail-title {
            font-size: 1.28rem;
            line-height: 1.14;
            letter-spacing: -0.04em;
            font-weight: 800;
            color: var(--text);
        }

        .detail-sub {
            margin-top: 8px;
            color: var(--sub);
            font-size: 0.94rem;
            line-height: 1.58;
            font-weight: 600;
        }

        .detail-badge-row {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
            margin-top: 12px;
        }

        .risk-pill {
            min-width: 54px;
            padding: 11px 0;
            border-radius: 999px;
            background: #f7f9fb;
            text-align: center;
            font-size: 1rem;
            font-weight: 800;
            color: var(--text);
            border: 1px solid rgba(15, 23, 42, 0.06);
        }

        .detail-grid {
            margin-top: 18px;
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 12px;
        }

        .detail-item {
            padding: 16px;
            border-radius: 16px;
            background: #f8fafc;
            border: 1px solid rgba(15, 23, 42, 0.06);
        }

        .detail-item-label {
            color: var(--muted);
            font-size: 0.82rem;
            font-weight: 700;
            margin-bottom: 8px;
        }

        .detail-item-value {
            color: var(--text);
            font-size: 1.32rem;
            line-height: 1;
            letter-spacing: -0.04em;
            font-weight: 800;
        }

        .section-shell {
            border-radius: var(--radius-lg);
            padding: 24px;
            margin-top: 16px;
        }

        .mix-list, .signal-list {
            margin-top: 18px;
            display: flex;
            flex-direction: column;
            gap: 18px;
        }

        .mix-row {
            display: grid;
            grid-template-columns: minmax(0, 1fr) 46px;
            gap: 12px;
            align-items: center;
        }

        .mix-name {
            color: var(--text);
            font-size: 0.98rem;
            font-weight: 800;
            margin-bottom: 8px;
        }

        .mix-track {
            height: 9px;
            border-radius: 999px;
            background: rgba(15, 23, 42, 0.06);
            overflow: hidden;
        }

        .mix-fill {
            height: 100%;
            border-radius: 999px;
        }

        .mix-count {
            text-align: right;
            color: var(--text);
            font-size: 1rem;
            font-weight: 800;
        }

        .signal-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 16px;
            padding: 6px 0;
            border-bottom: 1px solid rgba(15, 23, 42, 0.06);
        }

        .signal-row:last-child {
            border-bottom: 0;
        }

        .signal-label {
            color: var(--sub);
            font-size: 0.94rem;
            font-weight: 700;
        }

        .signal-value {
            color: var(--text);
            font-size: 1.7rem;
            line-height: 1;
            letter-spacing: -0.05em;
            font-weight: 800;
        }

        .insight-box {
            margin-top: 18px;
            padding: 18px 18px 6px;
            border-radius: 20px;
            background: #f8fbff;
            border: 1px solid rgba(49, 130, 246, 0.09);
        }

        .insight-row {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 14px;
            padding: 0 0 12px 0;
        }

        .insight-key {
            color: var(--muted);
            font-size: 0.9rem;
            font-weight: 700;
        }

        .insight-value {
            color: var(--text);
            font-size: 0.96rem;
            font-weight: 800;
            text-align: right;
        }

        [data-testid="stDataFrame"] {
            border: 1px solid rgba(15, 23, 42, 0.08);
            border-radius: 20px;
            overflow: hidden;
            background: rgba(255, 255, 255, 0.96);
        }

        [data-testid="stDataFrame"] [role="grid"] {
            border: 0 !important;
        }

        [data-testid="stDataFrame"] [role="columnheader"] {
            background: #f8fafc !important;
            font-weight: 800 !important;
            color: #4e5968 !important;
        }

        [data-testid="stDataFrame"] [role="gridcell"] {
            font-weight: 600;
            color: #191f28;
        }

        .empty-shell {
            border-radius: var(--radius-xl);
            padding: 78px 34px;
            text-align: center;
        }

        .empty-title {
            font-size: 2rem;
            line-height: 1.1;
            letter-spacing: -0.06em;
            font-weight: 800;
            color: var(--text);
        }

        .empty-copy {
            margin-top: 12px;
            color: var(--sub);
            font-size: 1rem;
            line-height: 1.68;
            font-weight: 600;
        }

        @media (max-width: 1120px) {
            .hero,
            .overview {
                grid-template-columns: 1fr;
            }

            .overview-item:not(:last-child)::after {
                display: none;
            }
        }

        @media (max-width: 760px) {
            .hero-title {
                font-size: 2.7rem;
            }

            .detail-grid {
                grid-template-columns: repeat(2, minmax(0, 1fr));
            }

            .detail-top {
                flex-direction: column;
            }
        }
        </style>
        """
    )


def load_data() -> pd.DataFrame:
    rows = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return pd.DataFrame(rows)


def format_timestamp(raw_value) -> str:
    if pd.isna(raw_value):
        return "-"
    if isinstance(raw_value, str):
        raw_value = raw_value.strip()
        if raw_value.isdigit():
            raw_value = int(raw_value)
        else:
            return raw_value
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

    if "label" not in normalized.columns:
        normalized["label"] = 0
    if "confidence" not in normalized.columns:
        normalized["confidence"] = 0.0
    if "timestamp" not in normalized.columns:
        normalized["timestamp"] = "-"

    normalized["label"] = normalized["label"].fillna(0).astype(int)
    normalized["confidence"] = normalized["confidence"].fillna(0.0).astype(float)
    normalized["display_time"] = normalized["timestamp"].map(format_timestamp)
    normalized["confidence_pct"] = (normalized["confidence"] * 100).round(1)
    normalized["status_name"] = normalized["label"].map(
        lambda value: LABEL_META.get(int(value), LABEL_META[0])["name"]
    )
    normalized["tone"] = normalized["label"].map(
        lambda value: LABEL_META.get(int(value), LABEL_META[0])["tone"]
    )
    normalized["risk_score"] = normalized["label"].map(
        lambda value: LABEL_META.get(int(value), LABEL_META[0])["risk"]
    )
    normalized["summary_text"] = normalized["label"].map(
        lambda value: LABEL_META.get(int(value), LABEL_META[0])["summary"]
    )
    return normalized


def topbar_html(total_count: int) -> str:
    return (
        '<div class="topbar">'
        '<div class="brand">'
        '<span class="brand-mark">A</span>'
        '<div>'
        '<div class="brand-title">AEGIS</div>'
        '<div class="brand-sub">Network Security Monitor</div>'
        "</div>"
        "</div>"
        '<div class="topbar-meta">'
        '<span class="meta-chip"><span class="meta-dot"></span>Live Dashboard</span>'
        f'<span class="meta-chip">데이터 {total_count:,}건</span>'
        "</div>"
        "</div>"
    )


def hero_html(latest: pd.Series, total_count: int, attack_ratio: float) -> str:
    tone = TONE_META[latest["tone"]]
    return (
        '<section class="shell hero">'
        '<div>'
        '<span class="hero-kicker">AEGIS LIVE SECURITY</span>'
        f'<div class="hero-title">{escape(str(latest["status_name"]))}</div>'
        f'<p class="hero-summary">{escape(str(latest["summary_text"]))}</p>'
        '<div class="hero-strip">'
        f'<span class="hero-pill"><span class="meta-dot"></span>자동 새로고침 {REFRESH_SECONDS}초</span>'
        f'<span class="hero-pill">마지막 감지 {escape(str(latest["display_time"]))}</span>'
        f'<span class="hero-pill">모델 신뢰 {latest["confidence_pct"]:.0f}%</span>'
        f'<span class="hero-pill">공격 비중 {attack_ratio:.0f}%</span>'
        "</div>"
        "</div>"
        '<div class="hero-side">'
        '<div>'
        '<div class="hero-side-label">현재 리스크</div>'
        f'<div class="hero-side-score">{int(latest["risk_score"])}</div>'
        f'<span class="hero-side-badge" style="background:{tone["soft"]};color:{tone["text"]};border-color:{tone["border"]};">{escape(str(latest["status_name"]))}</span>'
        "</div>"
        f'<div class="hero-side-meta">누적 이벤트 {total_count:,}<br>최근 탐지 {escape(str(latest["display_time"]))}</div>'
        "</div>"
        "</section>"
    )


def overview_html(
    latest: pd.Series,
    total_count: int,
    attack_count: int,
    attack_ratio: float,
    dominant_label: str,
) -> str:
    items = [
        ("현재 상태", str(latest["status_name"]), f"최근 탐지 {latest['display_time']}"),
        ("누적 이벤트", f"{total_count:,}", "관제 파이프라인 총 기록 수"),
        ("공격 비중", f"{attack_ratio:.0f}%", f"정상 제외 {attack_count:,}건"),
        ("주요 탐지 유형", dominant_label, "최근 누적 기준 최다 탐지"),
    ]

    body = "".join(
        (
            '<div class="overview-item">'
            f'<div class="overview-label">{escape(label)}</div>'
            f'<div class="overview-value">{escape(value)}</div>'
            f'<div class="overview-foot">{escape(foot)}</div>'
            "</div>"
        )
        for label, value, foot in items
    )
    return f'<section class="shell overview">{body}</section>'


def history_head_html() -> str:
    return (
        '<div class="shell section-head">'
        '<div class="section-kicker">Detection History</div>'
        '<div class="section-title">최근 탐지 내역</div>'
        '<div class="section-copy">스크롤로 목록을 확인하고, 행을 클릭하면 바로 아래에 세부 내역이 열립니다.</div>'
        "</div>"
    )


def history_table_frame(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    recent = df.iloc[::-1].head(MAX_HISTORY_ROWS).reset_index(drop=True).copy()
    table = pd.DataFrame(
        {
            "시간": recent["display_time"],
            "판정": recent["status_name"],
            "신뢰도": recent["confidence_pct"].map(lambda value: f"{value:.0f}%"),
            "리스크": recent["risk_score"].map(lambda value: int(value)),
            "패킷": recent["total_pkt_cnt"].fillna(0).map(lambda value: f"{int(value):,}"),
            "TCP": recent["tcp_cnt"].fillna(0).map(lambda value: f"{int(value):,}"),
            "UDP": recent["udp_cnt"].fillna(0).map(lambda value: f"{int(value):,}"),
        }
    )
    return recent, table


def detail_card_html(row: pd.Series) -> str:
    tone = TONE_META[row["tone"]]
    detail_items = [
        ("전체 패킷", int(row.get("total_pkt_cnt", 0) or 0)),
        ("TCP", int(row.get("tcp_cnt", 0) or 0)),
        ("UDP", int(row.get("udp_cnt", 0) or 0)),
        ("ICMP", int(row.get("icmp_cnt", 0) or 0)),
        ("DNS 질의", int(row.get("dns_query_cnt", 0) or 0)),
        ("SSH 실패", int(row.get("failed_login_cnt", 0) or 0)),
        ("대상 포트", int(row.get("unique_dst_port_cnt", 0) or 0)),
        ("출발지 IP", int(row.get("unique_src_ip_cnt", 0) or 0)),
    ]
    grid = "".join(
        (
            '<div class="detail-item">'
            f'<div class="detail-item-label">{escape(label)}</div>'
            f'<div class="detail-item-value">{value:,}</div>'
            "</div>"
        )
        for label, value in detail_items
    )
    return (
        '<div class="detail-card">'
        '<div class="detail-top">'
        "<div>"
        f'<div class="detail-title">{escape(str(row["status_name"]))} 세부 내역</div>'
        f'<div class="detail-sub">{escape(str(row["summary_text"]))}</div>'
        '<div class="detail-badge-row">'
        f'<span class="hero-pill">시간 {escape(str(row["display_time"]))}</span>'
        f'<span class="hero-pill">신뢰도 {row["confidence_pct"]:.0f}%</span>'
        f'<span class="hero-pill">Risk {int(row["risk_score"])}</span>'
        "</div>"
        "</div>"
        "<div>"
        f'<span class="risk-pill">{int(row["risk_score"])}</span>'
        f'<div><span class="tone-pill" style="background:{tone["soft"]};color:{tone["text"]};border-color:{tone["border"]};">{escape(str(row["status_name"]))}</span></div>'
        "</div>"
        "</div>"
        f'<div class="detail-grid">{grid}</div>'
        "</div>"
    )


def attack_mix_html(df: pd.DataFrame) -> str:
    counts = df["label"].value_counts().to_dict()
    max_count = max(counts.values()) if counts else 1
    order = [5, 3, 4, 2, 1, 0]
    rows = []
    for label in order:
        meta = LABEL_META[label]
        tone = TONE_META[meta["tone"]]
        count = int(counts.get(label, 0))
        width = 0 if count == 0 else max(8, int((count / max_count) * 100))
        rows.append(
            (
                '<div class="mix-row">'
                "<div>"
                f'<div class="mix-name">{escape(meta["name"])}</div>'
                '<div class="mix-track">'
                f'<div class="mix-fill" style="width:{width}%;background:{tone["accent"]};"></div>'
                "</div>"
                "</div>"
                f'<div class="mix-count">{count}</div>'
                "</div>"
            )
        )
    return (
        '<section class="shell section-shell">'
        '<div class="section-kicker">Traffic Pattern</div>'
        '<div class="section-title">유형별 분포</div>'
        '<div class="section-copy">누적 기록 기준으로 어떤 공격 유형이 많이 등장했는지 빠르게 읽을 수 있습니다.</div>'
        f'<div class="mix-list">{"".join(rows)}</div>'
        "</section>"
    )


def signal_panel_html(
    latest: pd.Series,
    total_count: int,
    attack_ratio: float,
    dominant_label: str,
) -> str:
    signal_rows = []
    for column, label in SIGNAL_ITEMS:
        value = int(latest.get(column, 0) or 0)
        signal_rows.append(
            (
                '<div class="signal-row">'
                f'<div class="signal-label">{escape(label)}</div>'
                f'<div class="signal-value">{value:,}</div>'
                "</div>"
            )
        )
    return (
        '<section class="shell section-shell">'
        '<div class="section-kicker">Live Snapshot</div>'
        '<div class="section-title">실시간 특징값</div>'
        '<div class="section-copy">패킷 수, DNS 질의, SSH 실패, 포트 다양성을 리스트 행으로 정리했습니다.</div>'
        f'<div class="signal-list">{"".join(signal_rows)}</div>'
        '<div class="insight-box">'
        '<div class="insight-row"><div class="insight-key">현재 판정</div>'
        f'<div class="insight-value">{escape(str(latest["status_name"]))}</div></div>'
        '<div class="insight-row"><div class="insight-key">마지막 감지</div>'
        f'<div class="insight-value">{escape(str(latest["display_time"]))}</div></div>'
        '<div class="insight-row"><div class="insight-key">누적 이벤트</div>'
        f'<div class="insight-value">{total_count:,}</div></div>'
        '<div class="insight-row"><div class="insight-key">공격 비중</div>'
        f'<div class="insight-value">{attack_ratio:.0f}%</div></div>'
        '<div class="insight-row"><div class="insight-key">최다 탐지</div>'
        f'<div class="insight-value">{escape(dominant_label)}</div></div>'
        "</div>"
        "</section>"
    )


def render_history_section(df: pd.DataFrame) -> None:
    recent, table = history_table_frame(df)
    render_html(history_head_html())

    selected_row = st.session_state.get("history_selected_row", 0)
    selected_row = max(0, min(selected_row, len(recent) - 1))

    try:
        event = st.dataframe(
            table,
            use_container_width=True,
            hide_index=True,
            height=430,
            on_select="rerun",
            selection_mode="single-row",
            key="history_table",
        )
        selected_rows = getattr(getattr(event, "selection", None), "rows", [])
        if selected_rows:
            selected_row = int(selected_rows[0])
            st.session_state["history_selected_row"] = selected_row
    except TypeError:
        option_labels = [
            f"{row['display_time']} · {row['status_name']} · 패킷 {int(row.get('total_pkt_cnt', 0) or 0):,}"
            for _, row in recent.iterrows()
        ]
        selected_label = st.selectbox(
            "세부 내역 보기",
            options=option_labels,
            index=selected_row,
            label_visibility="collapsed",
            key="history_selector",
        )
        selected_row = option_labels.index(selected_label)
        st.session_state["history_selected_row"] = selected_row
        st.dataframe(
            table,
            use_container_width=True,
            hide_index=True,
            height=430,
            key="history_table_fallback",
        )

    selected = recent.iloc[selected_row]
    render_html(detail_card_html(selected))


def empty_state_html() -> str:
    return (
        '<section class="shell empty-shell">'
        '<div class="empty-title">라이브 데이터 대기 중</div>'
        '<div class="empty-copy">feature extractor, predictor, monitor가 순서대로 실행되면 이 화면이 실시간 관제 화면으로 바뀝니다.</div>'
        "</section>"
    )


def render_dashboard(data: pd.DataFrame) -> None:
    latest = data.iloc[-1]
    total_count = len(data)
    attack_count = int((data["label"] != 0).sum())
    attack_ratio = (attack_count / total_count) * 100 if total_count else 0
    dominant_counts = data.loc[data["label"] != 0, "label"].value_counts()
    dominant_label = (
        LABEL_META[int(dominant_counts.index[0])]["name"]
        if not dominant_counts.empty
        else "정상 위주"
    )

    render_html(topbar_html(total_count))
    render_html(hero_html(latest, total_count, attack_ratio))
    render_html(overview_html(latest, total_count, attack_count, attack_ratio, dominant_label))

    left_col, right_col = st.columns([1.5, 1.0], gap="large")

    with left_col:
        render_history_section(data)
        render_html(attack_mix_html(data))

    with right_col:
        render_html(signal_panel_html(latest, total_count, attack_ratio, dominant_label))


inject_styles()

data = normalize_data(load_data())

if data.empty:
    render_html(empty_state_html())
else:
    render_dashboard(data)

time.sleep(REFRESH_SECONDS)
st.rerun()
