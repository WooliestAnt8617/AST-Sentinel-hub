"""
Analytics service — Aggregate query functions for the analytics dashboard.
All queries run against the SQLite database.
"""

import aiosqlite


async def get_impact_counters(db: aiosqlite.Connection, user_id: str | None = None) -> dict:
    """Get the four main impact counters for the dashboard."""
    w, p = ("WHERE user_id = ?", (user_id,)) if user_id else ("", ())
    cursor = await db.execute(f"SELECT COUNT(*) as count FROM audits {w}", p)
    row = await cursor.fetchone()
    total_audits = row["count"] if row else 0

    cursor = await db.execute(f"SELECT COUNT(DISTINCT language) as count FROM audits {w}", p)
    row = await cursor.fetchone()
    unique_languages = row["count"] if row else 0

    if user_id:
        cursor = await db.execute(
            "SELECT COUNT(*) as count FROM findings f "
            "WHERE f.audit_id IN (SELECT id FROM audits WHERE user_id = ?) "
            "AND f.severity = 'critical'",
            (user_id,),
        )
    else:
        cursor = await db.execute(
            "SELECT COUNT(*) as count FROM findings WHERE severity = 'critical'"
        )
    row = await cursor.fetchone()
    critical_issues = row["count"] if row else 0

    return {
        "total_audits": total_audits,
        "unique_languages": unique_languages,
        "critical_issues": critical_issues,
        "total_files": total_audits,
    }


async def get_top_languages(db: aiosqlite.Connection, limit: int = 10, user_id: str | None = None) -> list[dict]:
    """Get the most audited languages ranked by count."""
    w, p = ("WHERE user_id = ?", (user_id, limit)) if user_id else ("", (limit,))
    cursor = await db.execute(
        f"SELECT language, COUNT(*) as count FROM audits {w} GROUP BY language ORDER BY count DESC LIMIT ?", p
    )
    rows = await cursor.fetchall()
    return [{"language": r["language"], "count": r["count"]} for r in rows]


async def get_severity_distribution(db: aiosqlite.Connection, user_id: str | None = None) -> list[dict]:
    """Get the count of findings by severity level."""
    if user_id:
        cursor = await db.execute(
            "SELECT f.severity, COUNT(*) as count FROM findings f "
            "JOIN audits a ON f.audit_id = a.id WHERE a.user_id = ? "
            "GROUP BY f.severity ORDER BY CASE f.severity "
            "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 "
            "WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END",
            (user_id,),
        )
    else:
        cursor = await db.execute(
            "SELECT severity, COUNT(*) as count FROM findings "
            "GROUP BY severity ORDER BY CASE severity "
            "WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 "
            "WHEN 'low' THEN 4 WHEN 'info' THEN 5 ELSE 6 END"
        )
    rows = await cursor.fetchall()
    return [{"severity": r["severity"], "count": r["count"]} for r in rows]


async def get_category_breakdown(db: aiosqlite.Connection, user_id: str | None = None) -> list[dict]:
    """Get the count of findings by category."""
    if user_id:
        cursor = await db.execute(
            "SELECT f.category, COUNT(*) as count FROM findings f "
            "JOIN audits a ON f.audit_id = a.id WHERE a.user_id = ? "
            "GROUP BY f.category ORDER BY count DESC",
            (user_id,),
        )
    else:
        cursor = await db.execute(
            "SELECT category, COUNT(*) as count FROM findings GROUP BY category ORDER BY count DESC"
        )
    rows = await cursor.fetchall()
    return [{"category": r["category"], "count": r["count"]} for r in rows]


async def get_scores_over_time(db: aiosqlite.Connection, limit: int = 30, user_id: str | None = None) -> list[dict]:
    """Get average scores over recent audits (grouped by date)."""
    w, p = ("WHERE user_id = ?", (user_id, limit)) if user_id else ("", (limit,))
    cursor = await db.execute(
        f"SELECT DATE(created_at) as date, "
        f"ROUND(AVG(score_overall)) as avg_overall, "
        f"ROUND(AVG(score_security)) as avg_security, "
        f"ROUND(AVG(score_performance)) as avg_performance, "
        f"ROUND(AVG(score_maintainability)) as avg_maintainability, "
        f"COUNT(*) as audit_count "
        f"FROM audits {w} GROUP BY DATE(created_at) "
        f"ORDER BY date DESC LIMIT ?",
        p,
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
    results.reverse()
    return results


async def get_topic_severity_heatmap(db: aiosqlite.Connection, user_id: str | None = None) -> dict:
    """Get a topic × severity heatmap data structure."""
    if user_id:
        cursor = await db.execute(
            "SELECT t.topic, f.severity, COUNT(*) as count "
            "FROM topics t "
            "JOIN findings f ON t.audit_id = f.audit_id "
            "JOIN audits a ON t.audit_id = a.id "
            "WHERE a.user_id = ? "
            "GROUP BY t.topic, f.severity ORDER BY t.topic",
            (user_id,),
        )
    else:
        cursor = await db.execute(
            "SELECT t.topic, f.severity, COUNT(*) as count "
            "FROM topics t "
            "JOIN findings f ON t.audit_id = f.audit_id "
            "GROUP BY t.topic, f.severity ORDER BY t.topic"
        )
    rows = await cursor.fetchall()

    heatmap = {}
    severities = ["critical", "high", "medium", "low", "info"]
    for r in rows:
        topic = r["topic"]
        if topic not in heatmap:
            heatmap[topic] = {s: 0 for s in severities}
        heatmap[topic][r["severity"]] = r["count"]

    return {
        "severities": severities,
        "topics": [
            {"name": topic, "counts": [counts[s] for s in severities]}
            for topic, counts in sorted(heatmap.items())
        ],
    }


async def get_platform_health(db: aiosqlite.Connection, user_id: str | None = None) -> dict:
    """Get platform health metrics."""
    w, p = ("WHERE user_id = ?", (user_id,)) if user_id else ("", ())

    cursor = await db.execute(f"SELECT ROUND(AVG(score_overall), 1) as avg_score FROM audits {w}", p)
    row = await cursor.fetchone()
    avg_score = float(row["avg_score"]) if (row and row["avg_score"] is not None) else 0.0

    if user_id:
        cursor = await db.execute(
            "SELECT f.category, COUNT(*) as count FROM findings f "
            "JOIN audits a ON f.audit_id = a.id WHERE a.user_id = ? "
            "GROUP BY f.category ORDER BY count DESC LIMIT 1",
            (user_id,),
        )
    else:
        cursor = await db.execute(
            "SELECT category, COUNT(*) as count FROM findings GROUP BY category ORDER BY count DESC LIMIT 1"
        )
    row = await cursor.fetchone()
    most_common_category = row["category"] if row else "N/A"

    cursor = await db.execute(
        f"SELECT language, ROUND(AVG(score_overall), 1) as avg_score FROM audits {w} "
        f"GROUP BY language HAVING COUNT(*) >= 1 ORDER BY avg_score ASC LIMIT 3",
        p,
    )
    rows = await cursor.fetchall()
    worst_languages = [{"language": r["language"], "avg_score": float(r["avg_score"])} for r in rows]

    cursor = await db.execute(f"SELECT COUNT(*) as count FROM audits {w}", p)
    row = await cursor.fetchone()
    total = row["count"] if row else 0

    trend = "neutral"
    if total >= 4:
        cursor = await db.execute(
            f"SELECT score_overall FROM audits {w} ORDER BY created_at ASC", p
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


async def get_full_analytics(db: aiosqlite.Connection, user_id: str | None = None) -> dict:
    """Get all analytics data in one call, optionally scoped to a user."""
    return {
        "counters": await get_impact_counters(db, user_id),
        "top_languages": await get_top_languages(db, user_id=user_id),
        "severity_distribution": await get_severity_distribution(db, user_id),
        "category_breakdown": await get_category_breakdown(db, user_id),
        "scores_over_time": await get_scores_over_time(db, user_id=user_id),
        "heatmap": await get_topic_severity_heatmap(db, user_id),
        "platform_health": await get_platform_health(db, user_id),
    }
