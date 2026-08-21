"""Bento Box Design System & UI Renderers cho Project Sentinel Streamlit Dashboard."""

import streamlit as st


def inject_bento_css() -> None:
    """Inject custom CSS cho giao diện Bento Box Design (Glassmorphism + Dark Mode)."""
    st.markdown(
        """
        <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Outfit:wght@500;600;700&display=swap');

        /* Root styling & typography */
        html, body, [class*="css"] {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
        }

        h1, h2, h3, h4, .bento-header-title {
            font-family: 'Outfit', 'Inter', sans-serif !important;
            letter-spacing: -0.02em;
        }

        /* Bento Grid Card Base */
        .bento-card {
            background: linear-gradient(135deg, rgba(24, 24, 37, 0.95) 0%, rgba(30, 30, 46, 0.85) 100%);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 20px 24px;
            margin-bottom: 16px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.36);
            backdrop-filter: blur(12px);
            -webkit-backdrop-filter: blur(12px);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }

        .bento-card:hover {
            border-color: rgba(137, 180, 250, 0.4);
            transform: translateY(-2px);
            box-shadow: 0 12px 40px 0 rgba(137, 180, 250, 0.12);
        }

        .bento-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, #cba6f7, #89b4fa, #f5e0dc);
            opacity: 0.6;
        }

        /* Bento Metric Elements */
        .bento-icon {
            font-size: 28px;
            margin-bottom: 8px;
            display: inline-block;
        }

        .bento-title {
            color: #a6adc8;
            font-size: 13px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 6px;
        }

        .bento-value {
            color: #cdd6f4;
            font-size: 24px;
            font-weight: 700;
            line-height: 1.2;
            margin-bottom: 6px;
        }

        .bento-desc {
            color: #6c7086;
            font-size: 12px;
            font-weight: 400;
        }

        /* Quick link button inside Bento Cards */
        .bento-link-btn {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            background: linear-gradient(90deg, #a6e3a1 0%, #94e2d5 100%);
            color: #11111b !important;
            font-size: 13px;
            font-weight: 700;
            padding: 8px 14px;
            border-radius: 12px;
            text-decoration: none !important;
            margin-top: 10px;
            box-shadow: 0 4px 15px rgba(166, 227, 161, 0.25);
            transition: all 0.2s ease;
        }

        .bento-link-btn:hover {
            transform: scale(1.03);
            box-shadow: 0 6px 20px rgba(166, 227, 161, 0.4);
            color: #11111b !important;
        }

        /* Control Bento Box Wrapper */
        .bento-control-box {
            background: linear-gradient(135deg, rgba(24, 24, 37, 0.95) 0%, rgba(30, 30, 46, 0.85) 100%);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 20px 24px;
            margin-bottom: 16px;
            box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.36);
            backdrop-filter: blur(12px);
        }

        /* Grouped Vulnerability Card */
        .group-bento-card {
            background: rgba(30, 30, 46, 0.75);
            border: 1px solid rgba(49, 50, 68, 0.9);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 20px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
        }

        .group-bento-card.critical {
            border-left: 4px solid #f38ba8;
        }

        .group-bento-card.high {
            border-left: 4px solid #fab387;
        }

        .group-bento-card.medium {
            border-left: 4px solid #f9e2af;
        }

        .group-bento-card.low {
            border-left: 4px solid #89b4fa;
        }

        /* Badges */
        .bento-badge {
            display: inline-flex;
            align-items: center;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.03em;
            margin-right: 6px;
            margin-bottom: 4px;
        }

        .bento-badge.critical { background: rgba(243, 139, 168, 0.15); color: #f38ba8; border: 1px solid rgba(243, 139, 168, 0.4); }
        .bento-badge.high { background: rgba(250, 179, 135, 0.15); color: #fab387; border: 1px solid rgba(250, 179, 135, 0.4); }
        .bento-badge.medium { background: rgba(249, 226, 175, 0.15); color: #f9e2af; border: 1px solid rgba(249, 226, 175, 0.4); }
        .bento-badge.low { background: rgba(137, 180, 250, 0.15); color: #89b4fa; border: 1px solid rgba(137, 180, 250, 0.4); }
        .bento-badge.info { background: rgba(148, 226, 213, 0.15); color: #94e2d5; border: 1px solid rgba(148, 226, 213, 0.4); }
        .bento-badge.success { background: rgba(166, 227, 161, 0.15); color: #a6e3a1; border: 1px solid rgba(166, 227, 161, 0.4); }
        .bento-badge.default { background: rgba(49, 50, 68, 0.6); color: #cdd6f4; border: 1px solid rgba(205, 214, 244, 0.2); }

        /* Code block adjustments */
        div[data-aria-label="st.code"] {
            border-radius: 12px;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def render_bento_card(
    title: str,
    value: str,
    description: str = "",
    icon: str = "🛡️",
    badge_text: str | None = None,
    badge_variant: str = "info",
    link_url: str | None = None,
    link_label: str = "Mở liên kết ↗",
) -> None:
    """Render 1 thẻ Bento Card chuẩn visual design kèm tùy chọn nút Quick Link."""
    badge_html = ""
    if badge_text:
        badge_html = f'<span class="bento-badge {badge_variant.lower()}">{badge_text}</span>'

    link_html = ""
    if link_url:
        link_html = f'<a href="{link_url}" target="_blank" class="bento-link-btn">{link_label}</a>'

    st.markdown(
        f"""
        <div class="bento-card">
            <div style="display: flex; justify-content: space-between; align-items: flex-start;">
                <div class="bento-icon">{icon}</div>
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


def render_bento_header(title: str, subtitle: str = "", icon: str = "🛡️") -> None:
    """Render Section Header chuẩn Bento Style."""
    st.markdown(
        f"""
        <div style="margin-top: 12px; margin-bottom: 16px;">
            <h2 class="bento-header-title" style="display: flex; align-items: center; gap: 10px; font-size: 24px; font-weight: 700; color: #cdd6f4; margin: 0;">
                <span>{icon}</span> {title}
            </h2>
            <p style="color: #a6adc8; font-size: 14px; margin-top: 4px; margin-bottom: 0;">{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.divider()
