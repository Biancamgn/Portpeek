"""
portpeek.report
==============

Output layer, kept separate from the scan engine so the same results can be
rendered two ways:

    console      -> colored terminal output for the live demo
    html_report  -> a self-contained HTML file (the twist's deliverable)
"""

from . import console, html_report

__all__ = ["console", "html_report"]
