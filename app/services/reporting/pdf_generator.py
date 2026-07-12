from io import BytesIO

from flask import render_template
from weasyprint import HTML


def render_report_html(report, executive_summary, generated_at) -> str:
    """Renders the full HTML report template to a string, given the
    same context the report-preview route already builds. Separated
    from PDF generation itself so the HTML-rendering step can be
    tested/reused independently (e.g. the existing report-preview
    route can eventually be refactored to call this too, avoiding
    duplicated render_template context-building logic).
    """
    return render_template(
        "reports/report.html",
        report=report,
        executive_summary=executive_summary,
        generated_at=generated_at,
    )


def generate_pdf(html_content: str) -> bytes:
    """Converts an HTML string into PDF bytes using WeasyPrint.

    Must be called within an active Flask application/request context,
    since render_report_html() (typically called just before this)
    uses Flask's render_template, which requires one.
    """
    pdf_buffer = BytesIO()
    HTML(string=html_content).write_pdf(pdf_buffer)
    return pdf_buffer.getvalue()
