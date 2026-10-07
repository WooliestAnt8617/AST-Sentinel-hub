"""
Analytics service — Aggregate query functions for the analytics dashboard.
All queries run against the SQLite database.
"""

import aiosqlite


async def get_impact_counters(db: aiosqlite.Connection) -> dict:
    """Get the four main impact counters for the dashboard."""
    # Total audits
    cursor = await db.execute("SELECT COUNT(*) as count FROM audits")
    row = await cursor.fetchone()
    total_audits = row["count"]

    # Unique languages
    cursor = await db.execute("SELECT COUNT(DISTINCT language) as count FROM audits")
    row = await cursor.fetchone()
    unique_languages = row["count"]

    # Critical issues found
    cursor = await db.execute(
        "SELECT COUNT(*) as count FROM findings WHERE severity = 'critical'"
    )
    row = await cursor.fetchone()
    critical_issues = row["count"]

    # Total files analyzed
    cursor = await db.execute("SELECT COUNT(*) as count FROM audits")
    row = await cursor.fetchone()
    total_files = row["count"]

    return {
        "total_audits": total_audits,
        "unique_languages": unique_languages,
        "critical_issues": critical_issues,
        "total_files": total_files,
    }


async def get_top_languages(db: aiosqlite.Connection, limit: int = 10) -> list[dict]:
    """Get the most audited languages ranked by count."""
    cursor = await db.execute(
        "SELECT language, COUNT(*) as count FROM audits "
        "GROUP BY language ORDER BY count DESC LIMIT ?",
        (limit,),
    )
    rows = await cursor.fetchall()
    return [{"language": r["language"], "count": r["count"]} for r in rows]


async def get_severity_distribution(db: aiosqlite.Connection) -> list[dict]:
    """Get the count of findings by severity level."""
    cursor = await db.execute(
        "SELECT severity, COUNT(*) as count FROM findings "
        "GROUP BY severity ORDER BY CASE severity "
        "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 "
        "WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END"
    )
    rows = await cursor.fetchall()
    return [{"severity": r["severity"], "count": r["count"]} for r in rows]


async def get_category_breakdown(db: aiosqlite.Connection) -> list[dict]:
    """Get the count of findings by category."""
    cursor = await db.execute(
        "SELECT category, COUNT(*) as count FROM findings "
        "GROUP BY category ORDER BY count DESC"
    )
    rows = await cursor.fetchall()
    return [{"category": r["category"], "count": r["count"]} for r in rows]


async def get_scores_over_time(db: aiosqlite.Connection, limit: int = 30) -> list[dict]:
    """Get average scores over recent audits (grouped by date)."""
    cursor = await db.execute(
        "SELECT DATE(created_at) as date, "
        "ROUND(AVG(score_overall)) as avg_overall, "
        "ROUND(AVG(score_security)) as avg_security, "
        "ROUND(AVG(score_performance)) as avg_performance, "
        "ROUND(AVG(score_maintainability)) as avg_maintainability, "
        "COUNT(*) as audit_count "
        "FROM audits GROUP BY DATE(created_at) "
        "ORDER BY date DESC LIMIT ?",
        (limit,),
    )
    rows = await cursor.fetchall()
    results = [
        {
            "date": r["date"],
            "avg_overall": int(r["avg_overall"] or 0),
            "avg_security": int(r["avg_security"] or 0),
            "avg_performance": int(r["avg_performance"] or 0),
            "avg_maintainability": int(r["avg_maintainability"] or 0),
            "audit_count": r["audit_count"],
        }
        for r in rows
    ]
    results.reverse()  # chronological order
    return results


async def get_topic_severity_heatmap(db: aiosqlite.Connection) -> dict:
    """Get a topic × severity heatmap data structure."""
    cursor = await db.execute(
        "SELECT t.topic, f.severity, COUNT(*) as count "
        "FROM topics t "
        "JOIN findings f ON t.audit_id = f.audit_id "
        "GROUP BY t.topic, f.severity "
        "ORDER BY t.topic"
    )
    rows = await cursor.fetchall()

    # Build heatmap: { topic: { severity: count } }
    heatmap = {}
    severities = ["critical", "high", "medium", "low", "info"]
    for r in rows:
        topic = r["topic"]
        if topic not in heatmap:
            heatmap[topic] = {s: 0 for s in severities}
        heatmap[topic][r["severity"]] = r["count"]

    # Convert to list format for easy template rendering
    result = {
        "severities": severities,
        "topics": [
            {"name": topic, "counts": [counts[s] for s in severities]}
            for topic, counts in sorted(heatmap.items())
        ],
    }
    return result


async def get_platform_health(db: aiosqlite.Connection) -> dict:
    """Get platform health metrics."""
    # Average overall score
    cursor = await db.execute(
        "SELECT ROUND(AVG(score_overall), 1) as avg_score FROM audits"
    )
    row = await cursor.fetchone()
    avg_score = float(row["avg_score"]) if row["avg_score"] else 0

    # Most common issue category
    cursor = await db.execute(
        "SELECT category, COUNT(*) as count FROM findings "
        "GROUP BY category ORDER BY count DESC LIMIT 1"
    )
    row = await cursor.fetchone()
    most_common_category = row["category"] if row else "N/A"

    # Languages with worst average scores
    cursor = await db.execute(
        "SELECT language, ROUND(AVG(score_overall), 1) as avg_score "
        "FROM audits GROUP BY language "
        "HAVING COUNT(*) >= 1 "
        "ORDER BY avg_score ASC LIMIT 3"
    )
    rows = await cursor.fetchall()
    worst_languages = [
        {"language": r["language"], "avg_score": float(r["avg_score"])}
        for r in rows
    ]

    # Improvement trend: compare first half vs second half of audits
    cursor = await db.execute("SELECT COUNT(*) as count FROM audits")
    row = await cursor.fetchone()
    total = row["count"]

    trend = "neutral"
    if total >= 4:
        cursor = await db.execute(
            "SELECT score_overall FROM audits ORDER BY created_at ASC"
        )
        all_scores = [r["score_overall"] for r in await cursor.fetchall()]
        mid = len(all_scores) // 2
        first_half_avg = sum(all_scores[:mid]) / mid if mid > 0 else 0
        second_half_avg = sum(all_scores[mid:]) / (len(all_scores) - mid) if (len(all_scores) - mid) > 0 else 0
        if second_half_avg > first_half_avg + 2:
            trend = "improving"
        elif second_half_avg < first_half_avg - 2:
            trend = "declining"

    return {
        "avg_score": avg_score,
        "most_common_category": most_common_category,
        "worst_languages": worst_languages,
        "trend": trend,
        "total_audits": total,
    }


async def get_full_analytics(db: aiosqlite.Connection) -> dict:
    """Get all analytics data in one call."""
    return {
        "counters": await get_impact_counters(db),
        "top_languages": await get_top_languages(db),
        "severity_distribution": await get_severity_distribution(db),
        "category_breakdown": await get_category_breakdown(db),
        "scores_over_time": await get_scores_over_time(db),
        "heatmap": await get_topic_severity_heatmap(db),
        "platform_health": await get_platform_health(db),
    }
