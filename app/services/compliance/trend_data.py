from app.models.scan import Scan
from app.services.risk_scoring import calculate_risk_score


def get_score_trend_data(website_id: int) -> dict:
    """Returns chart-ready trend data for a website's completed scan
    history: chronologically ordered labels (scan dates) and their
    corresponding overall risk scores.

    Returns a dict shaped for direct use as Chart.js's `data` config
    object (labels + a single dataset), rather than a more generic
    intermediate structure — since trend charting is this data's only
    consumer, there's no benefit to a more abstract shape that would
    just need reformatting again before reaching the frontend.
    """
    scans = (
        Scan.query.filter_by(website_id=website_id, status="completed")
        .order_by(Scan.started_at.asc())
        .all()
    )

    labels = [scan.started_at.strftime("%Y-%m-%d") for scan in scans]
    scores = [calculate_risk_score(scan.findings) for scan in scans]

    return {
        "labels": labels,
        "scores": scores,
    }
