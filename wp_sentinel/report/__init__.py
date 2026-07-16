"""Report renderers for scan results (JSON, HTML, CSV, SARIF, Markdown)."""

from .json_report import render_json
from .html_report import render_html
from .csv_report import render_csv
from .sarif_report import render_sarif
from .markdown_report import render_markdown

_RENDERERS = {
    "json": render_json,
    "html": render_html,
    "csv": render_csv,
    "sarif": render_sarif,
    "markdown": render_markdown,
    "md": render_markdown,
}

#: Media type per format name, for the HTTP API.
MEDIA_TYPES = {
    "json": "application/json",
    "html": "text/html",
    "csv": "text/csv",
    "sarif": "application/json",
    "markdown": "text/markdown",
    "md": "text/markdown",
}


def render(fmt: str, result) -> str:
    """Render ``result`` in the requested format.

    Supported: ``json``, ``html``, ``csv``, ``sarif``, ``markdown`` (``md``).
    """
    try:
        renderer = _RENDERERS[fmt]
    except KeyError:
        available = ", ".join(sorted(_RENDERERS))
        raise KeyError(f"Unknown report format {fmt!r}. Available: {available}.") from None
    return renderer(result)


__all__ = [
    "render",
    "render_json",
    "render_html",
    "render_csv",
    "render_sarif",
    "render_markdown",
    "MEDIA_TYPES",
]
