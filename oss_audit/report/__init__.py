"""
report — renders an AuditResult to JSON, Markdown, and HTML.

Public API:
    to_json(result)      -> str
    to_markdown(result)  -> str
    to_html(result)      -> str
"""

from ._json import to_json
from ._markdown import to_markdown
from ._html import to_html

__all__ = ["to_json", "to_markdown", "to_html"]
