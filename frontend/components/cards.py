"""Component renderers và UI cards cho Streamlit Dashboard."""

import streamlit as st

try:
    import streamlit_shadcn_ui as ui
    SHADCN_AVAILABLE = True
except ImportError:
    SHADCN_AVAILABLE = False


def render_metric_card(title: str, content: str, description: str = "", key: str | None = None):
    """Render Metric Card bằng streamlit-shadcn-ui hoặc fallback HTML."""
    if SHADCN_AVAILABLE and hasattr(ui, "metric_card"):
        ui.metric_card(title=title, content=content, description=description, key=key)
    else:
        st.markdown(
            f"""
            <div style="background-color: #1e1e2e; padding: 16px; border-radius: 8px; border: 1px solid #313244; margin-bottom: 12px;">
                <div style="color: #a6adc8; font-size: 14px; font-weight: 500;">{title}</div>
                <div style="color: #cdd6f4; font-size: 24px; font-weight: 700; margin: 4px 0;">{content}</div>
                <div style="color: #6c7086; font-size: 12px;">{description}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_badge(text: str, variant: str = "default"):
    """
    Render Badge cho Severity / Tool / Status.
    Variants: 'critical', 'high', 'medium', 'low', 'info', 'default', 'success'
    """
    colors = {
        "critical": ("#f38ba8", "#31131e"),
        "high": ("#fab387", "#362219"),
        "medium": ("#f9e2af", "#38311a"),
        "low": ("#89b4fa", "#1c2b42"),
        "info": ("#94e2d5", "#193532"),
        "success": ("#a6e3a1", "#1e3725"),
        "default": ("#cdd6f4", "#313244"),
    }
    fg, bg = colors.get(variant.lower(), colors["default"])
    
    if SHADCN_AVAILABLE and hasattr(ui, "badge"):
        try:
            ui.badge(text=text, variant=variant)
            return
        except Exception:  # noqa: S110, BLE001
            pass

    st.markdown(
        f'<span style="background-color: {bg}; color: {fg}; padding: 4px 8px; border-radius: 6px; font-size: 12px; font-weight: 600; border: 1px solid {fg}40; display: inline-block; margin-right: 4px;">{text}</span>',
        unsafe_allow_html=True,
    )


def render_section_header(title: str, subtitle: str = ""):
    """Render Section Header chuẩn UI."""
    st.markdown(f"### {title}")
    if subtitle:
        st.markdown(f"*{subtitle}*")
    st.divider()
