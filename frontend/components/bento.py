"""Bento Box Design System & UI Renderers cho Project Sentinel Streamlit Dashboard.

Tích hợp Material Symbols Outlined, Dark Glassmorphism, Real-time Log Streaming Boxes,
và Executive Threat & Guardrails KPI Grids.
"""

from __future__ import annotations

import streamlit as st


def inject_bento_css() -> None:
    """Inject custom CSS cho giao diện Bento Box Design (Glassmorphism + Dark Mode)."""
    css_content = (
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined" />\n'
        '<style>\n'
        "@import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined');\n"
        "@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=Outfit:wght@500;600;700&display=swap');\n"
        "html, body, .stApp { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }\n"
        "h1, h2, h3, h4, .bento-header-title { font-family: 'Outfit', 'Inter', sans-serif !important; letter-spacing: -0.02em; }\n"
        ".material-symbols-outlined { font-family: 'Material Symbols Outlined' !important; font-weight: normal; font-style: normal; font-size: 20px; line-height: 1; letter-spacing: normal; text-transform: none; display: inline-block; white-space: nowrap; word-wrap: normal; direction: ltr; vertical-align: middle; -webkit-font-smoothing: antialiased; text-rendering: optimizeLegibility; -moz-osx-font-smoothing: grayscale; font-feature-settings: 'liga'; }\n"
        ".bento-card { background: linear-gradient(135deg, rgba(24, 24, 37, 0.95) 0%, rgba(30, 30, 46, 0.85) 100%); border: 1px solid rgba(255, 255, 255, 0.08); border-radius: 16px; padding: 18px 22px; margin-bottom: 14px; box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.36); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); position: relative; overflow: hidden; }\n"
        ".bento-card:hover { border-color: rgba(77, 142, 255, 0.4); transform: translateY(-2px); box-shadow: 0 12px 40px 0 rgba(77, 142, 255, 0.12); }\n"
        ".bento-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, #4D8EFF, #4EDEA3, #cba6f7); opacity: 0.7; }\n"
        ".bento-title { color: #a6adc8; font-size: 12px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }\n"
        ".bento-value { color: #cdd6f4; font-size: 22px; font-weight: 700; line-height: 1.2; margin-bottom: 4px; }\n"
        ".bento-desc { color: #6c7086; font-size: 12px; font-weight: 400; }\n"
        ".bento-terminal-box { background-color: #0b1326; border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 12px; padding: 10px 14px; font-family: 'Fira Code', 'Roboto Mono', monospace; font-size: 12px; line-height: 1.5; color: #4edea3; overflow-y: auto; white-space: pre-wrap; word-break: break-all; margin-top: 8px; margin-bottom: 12px; box-shadow: inset 0 2px 8px rgba(0, 0, 0, 0.6); }\n"
        ".bento-badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 10px; border-radius: 20px; font-size: 11px; font-weight: 700; letter-spacing: 0.03em; margin-right: 6px; margin-bottom: 4px; }\n"
        ".bento-badge.critical { background: rgba(243, 139, 168, 0.15); color: #f38ba8; border: 1px solid rgba(243, 139, 168, 0.4); }\n"
        ".bento-badge.high { background: rgba(250, 179, 135, 0.15); color: #fab387; border: 1px solid rgba(250, 179, 135, 0.4); }\n"
        ".bento-badge.medium { background: rgba(249, 226, 175, 0.15); color: #f9e2af; border: 1px solid rgba(249, 226, 175, 0.4); }\n"
        ".bento-badge.low { background: rgba(137, 180, 250, 0.15); color: #89b4fa; border: 1px solid rgba(137, 180, 250, 0.4); }\n"
        ".bento-badge.info { background: rgba(148, 226, 213, 0.15); color: #94e2d5; border: 1px solid rgba(148, 226, 213, 0.4); }\n"
        ".bento-badge.success { background: rgba(166, 227, 161, 0.15); color: #a6e3a1; border: 1px solid rgba(166, 227, 161, 0.4); }\n"
        ".bento-badge.default { background: rgba(49, 50, 68, 0.6); color: #cdd6f4; border: 1px solid rgba(205, 214, 244, 0.2); }\n"
        "</style>"
    )
    st.markdown(css_content, unsafe_allow_html=True)


def format_material_icon(icon_name: str, size: int = 20, color: str | None = None) -> str:
    """Return HTML string for Google Material Symbols Outlined."""
    color_style = f" color: {color};" if color else ""
    return f'<span class="material-symbols-outlined" style="font-size: {size}px;{color_style}">{icon_name}</span>'


def build_security_badge_html(text: str, variant: str = "info", icon: str | None = None) -> str:
    """Build HTML for a rounded security badge with optional Material Symbol."""
    icon_html = f"{format_material_icon(icon, size=14)} " if icon else ""
    return f'<span class="bento-badge {variant.lower()}">{icon_html}{text}</span>'


def build_realtime_log_box_html(log_text: str, max_height: str = "120px") -> str:
    """Build HTML for scrollable streaming log box."""
    safe_log = log_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f'<div class="bento-terminal-box" style="max-height: {max_height}; overflow-y: auto;">{safe_log}</div>'


def render_realtime_log_box(log_text: str, max_height: str = "120px") -> None:
    """Render scrollable real-time streaming log box in Streamlit."""
    st.markdown(build_realtime_log_box_html(log_text, max_height=max_height), unsafe_allow_html=True)


def build_guardrails_kpi_grid_html(
    pii_count: int = 0,
    injection_count: int = 0,
    approved_count: int = 0,
    rejected_count: int = 0,
    mean_latency_ms: float = 0.0,
    total_groups: int = 0,
    confirmed_tp: int = 0,
    false_positives: int = 0,
) -> str:
    """Generate HTML grid for Guardrails & Threat Metrics in Tab 5."""
    return f"""
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 16px;">
        <div class="bento-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span class="material-symbols-outlined" style="font-size: 26px; color: #4EDEA3;">shield</span>
                <span class="bento-badge success">Active</span>
            </div>
            <div class="bento-title">PII Masked</div>
            <div class="bento-value">{pii_count}</div>
            <div class="bento-desc">Emails, Passwords, Tokens</div>
        </div>
        <div class="bento-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span class="material-symbols-outlined" style="font-size: 26px; color: #fab387;">gpp_maybe</span>
                <span class="bento-badge high">Neutralized</span>
            </div>
            <div class="bento-title">Injections Neutralized</div>
            <div class="bento-value">{injection_count}</div>
            <div class="bento-desc">Prompt Injections Isolated</div>
        </div>
        <div class="bento-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span class="material-symbols-outlined" style="font-size: 26px; color: #4D8EFF;">gavel</span>
                <span class="bento-badge info">Gate</span>
            </div>
            <div class="bento-title">HITL Decisions</div>
            <div class="bento-value">{approved_count} / {approved_count + rejected_count}</div>
            <div class="bento-desc">Approved / Total Probes</div>
        </div>
        <div class="bento-card">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <span class="material-symbols-outlined" style="font-size: 26px; color: #cba6f7;">speed</span>
                <span class="bento-badge default">Gateway</span>
            </div>
            <div class="bento-title">Mean Gateway Latency</div>
            <div class="bento-value">{mean_latency_ms:.1f}ms</div>
            <div class="bento-desc">{total_groups} Groups ({confirmed_tp} TP / {false_positives} FP)</div>
        </div>
    </div>
    """


def render_guardrails_kpi_grid(
    pii_count: int = 0,
    injection_count: int = 0,
    approved_count: int = 0,
    rejected_count: int = 0,
    mean_latency_ms: float = 0.0,
    total_groups: int = 0,
    confirmed_tp: int = 0,
    false_positives: int = 0,
) -> None:
    """Render the 4-card Guardrails & Threat Metrics grid in Streamlit."""
    html = build_guardrails_kpi_grid_html(
        pii_count=pii_count,
        injection_count=injection_count,
        approved_count=approved_count,
        rejected_count=rejected_count,
        mean_latency_ms=mean_latency_ms,
        total_groups=total_groups,
        confirmed_tp=confirmed_tp,
        false_positives=false_positives,
    )
    st.markdown(html, unsafe_allow_html=True)


def render_bento_card(
    title: str,
    value: str,
    description: str = "",
    icon: str = "security",
    badge_text: str | None = None,
    badge_variant: str = "info",
    link_url: str | None = None,
    link_label: str = "Mở liên kết ↗",
) -> None:
    """Render 1 thẻ Bento Card chuẩn visual design kèm Material Symbol và Quick Link."""
    badge_html = ""
    if badge_text:
        badge_html = f'<span class="bento-badge {badge_variant.lower()}">{badge_text}</span>'

    link_html = ""
    if link_url:
        link_html = f'<a href="{link_url}" target="_blank" style="color: #4D8EFF; font-size: 12px; font-weight: 600; text-decoration: none; margin-top: 6px; display: inline-block;">{link_label}</a>'

    icon_html = format_material_icon(icon, size=24, color="#4D8EFF")

    st.markdown(
        f"""
        <div class="bento-card">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                <div>{icon_html}</div>
                {badge_html}
            </div>
            <div class="bento-title">{title}</div>
            <div class="bento-value">{value}</div>
            <div class="bento-desc">{description}</div>
            {link_html}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_bento_header(title: str, subtitle: str = "", icon: str = "security") -> None:
    """Render Section Header chuẩn Bento Style với Material Symbols."""
    icon_html = format_material_icon(icon, size=26, color="#4D8EFF")
    render_clean_html(
        f"""
        <div style="margin-top: 10px; margin-bottom: 14px;">
            <h2 class="bento-header-title" style="display: flex; align-items: center; gap: 8px; font-size: 22px; font-weight: 700; color: #cdd6f4; margin: 0;">
                {icon_html} <span>{title}</span>
            </h2>
            <p style="color: #a6adc8; font-size: 13px; margin-top: 4px; margin-bottom: 0;">{subtitle}</p>
        </div>
        """
    )
    st.divider()


def render_clean_html(html_str: str) -> None:
    """Render HTML an toàn, loại bỏ triệt để khoảng trắng thụt lề nhằm tránh lỗi 4-space code block của Markdown."""
    lines = [line.strip() for line in html_str.splitlines() if line.strip()]
    st.markdown("".join(lines), unsafe_allow_html=True)
