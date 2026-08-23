"""Component renderers và UI cards cho Streamlit Dashboard (Bento Box + Shadcn UI)."""

from __future__ import annotations

import streamlit as st

from frontend.components.bento import format_material_icon, render_bento_card, render_bento_header


def render_metric_card(
    title: str,
    content: str,
    description: str = "",
    key: str | None = None,
    icon: str = "analytics",
    badge_text: str | None = None,
    badge_variant: str = "info",
) -> None:
    """Render Metric Card bằng Bento Card styling chuẩn Shadcn UI."""
    render_bento_card(
        title=title,
        value=content,
        description=description,
        icon=icon,
        badge_text=badge_text,
        badge_variant=badge_variant,
    )


def render_badge(text: str, variant: str = "default", icon: str | None = None) -> None:
    """
    Render Badge chuẩn Bento / Shadcn style cho Severity / Tool / Status.
    Variants: 'critical', 'high', 'medium', 'low', 'info', 'default', 'success'
    """
    v_clean = variant.lower()
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
    icon_html = f"{format_material_icon(icon, size=13)} " if icon else ""

    st.markdown(
        f'<span style="background-color: {bg}; color: {fg}; padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700; border: 1px solid {border}; display: inline-flex; align-items: center; gap: 4px; margin-right: 6px; margin-bottom: 4px; letter-spacing: 0.03em;">{icon_html}{text}</span>',
        unsafe_allow_html=True,
    )


def render_section_header(title: str, subtitle: str = "", icon: str = "security") -> None:
    """Render Section Header chuẩn UI Bento Box với Material Symbol."""
    render_bento_header(title=title, subtitle=subtitle, icon=icon)
