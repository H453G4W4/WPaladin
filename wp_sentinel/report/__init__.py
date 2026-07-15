"""Report renderers for scan results (JSON, HTML, CSV)."""

from .json_report import render_json
from .html_report import render_html
from .csv_report import render_csv

_RENDERERS = {
    "json": render_json,
    "html": render_html,
    "csv": render_csv,
}


def render(fmt: str, result) -> str:
    """Render ``result`` in the requested format ('json', 'html', or 'csv')."""
    try:
        renderer = _RENDERERS[fmt]
    except KeyError:
        available = ", ".join(sorted(_RENDERERS))
        raise KeyError(f"Unknown report format {fmt!r}. Available: {available}.") from None
    return renderer(result)


__all__ = ["render", "render_json", "render_html", "render_csv"]
