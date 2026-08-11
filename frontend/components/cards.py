"""Component renderers và UI cards cho Streamlit Dashboard (Bento Box Enhanced)."""

import streamlit as st

try:
    import streamlit_shadcn_ui as ui
    SHADCN_AVAILABLE = True
except ImportError:
    SHADCN_AVAILABLE = False

from frontend.components.bento import render_bento_card, render_bento_header


def render_metric_card(
    title: str,
    content: str,
    description: str = "",
    key: str | None = None,
    icon: str = "📊",
    badge_text: str | None = None,
    badge_variant: str = "info",
) -> None:
    """Render Metric Card bằng Bento Card styling hoặc fallback shadcn-ui."""
    if SHADCN_AVAILABLE and hasattr(ui, "metric_card") and not badge_text:
        ui.metric_card(label=title, value=content, description=description, key=key)
    else:
        render_bento_card(
            title=title,
            value=content,
            description=description,
            icon=icon,
            badge_text=badge_text,
            badge_variant=badge_variant,
        )


def render_badge(text: str, variant: str = "default") -> None:
    """
    Render Badge chuẩn Bento / Shadcn style cho Severity / Tool / Status.
    Variants: 'critical', 'high', 'medium', 'low', 'info', 'default', 'success'
    """
    v_clean = variant.lower()
    if SHADCN_AVAILABLE and hasattr(ui, "badge"):
        try:
            ui.badge(text=text, variant=v_clean)
            return
        except Exception:  # noqa: S110, BLE001
            pass

    colors = {
        "critical": ("#f38ba8", "rgba(243, 139, 168, 0.15)", "rgba(243, 139, 168, 0.4)"),
        "high": ("#fab387", "rgba(250, 179, 135, 0.15)", "rgba(250, 179, 135, 0.4)"),
        "medium": ("#f9e2af", "rgba(249, 226, 175, 0.15)", "rgba(249, 226, 175, 0.4)"),
        "low": ("#89b4fa", "rgba(137, 180, 250, 0.15)", "rgba(137, 180, 250, 0.4)"),
        "info": ("#94e2d5", "rgba(148, 226, 213, 0.15)", "rgba(148, 226, 213, 0.4)"),
        "success": ("#a6e3a1", "rgba(166, 227, 161, 0.15)", "rgba(166, 227, 161, 0.4)"),
        "default": ("#cdd6f4", "rgba(49, 50, 68, 0.6)", "rgba(205, 214, 244, 0.2)"),
    }
    fg, bg, border = colors.get(v_clean, colors["default"])

    st.markdown(
        f'<span style="background-color: {bg}; color: {fg}; padding: 4px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; border: 1px solid {border}; display: inline-block; margin-right: 6px; margin-bottom: 4px; letter-spacing: 0.03em;">{text}</span>',
        unsafe_allow_html=True,
    )


def render_section_header(title: str, subtitle: str = "", icon: str = "🛡️") -> None:
    """Render Section Header chuẩn UI Bento Box."""
    render_bento_header(title=title, subtitle=subtitle, icon=icon)
