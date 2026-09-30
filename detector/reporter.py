"""Render alerts as a Markdown incident report."""


def to_markdown(alerts):
    """Convert a list of alert dicts into a Markdown report string."""
    lines = ["# Login Anomaly Report", "", f"**Alerts:** {len(alerts)}", ""]
    for i, a in enumerate(alerts, 1):
        lines.append(f"## Alert {i}: {a['type'].upper()} ({a['severity']})")
        lines.append(f"- **Source IP:** {a['src_ip']}")
        if a["type"] == "bruteforce":
            lines.append(f"- **Target user:** {a['user']}")
            lines.append(f"- **Failed attempts:** {a['count']}")
        else:
            lines.append(f"- **Targeted users ({a['count']}):** {', '.join(a['users'])}")
        lines.append(f"- **Window:** {a['window_start']} -> {a['window_end']}")
        lines.append("")
    return "\n".join(lines)
