def load_logs(filename):
    """Load log lines from a file."""
    with open(filename) as file:
        return file.readlines()


def parse_log(line):
    """Convert one log line into a dictionary."""
    parts = line.split()

    if len(parts) != 4:
        raise ValueError("Invalid log format")

    return {
        "date": parts[0],
        "time": parts[1],
        "event": parts[2],
        "ip": parts[3]
    }


def analyze_events(events):
    """Calculate basic statistics from log events."""
    total = 0
    failed = 0
    successful = 0

    for event in events:
        total += 1

        if event["event"] == "LOGIN_FAILED":
            failed += 1

        elif event["event"] == "LOGIN_SUCCESS":
            successful += 1

    return {
        "total": total,
        "failed": failed,
        "successful": successful
    }


def detect_suspicious_activity(events, threshold=3):
    """Find IP addresses with repeated failed login attempts."""
    failed_attempts = {}

    for event in events:
        if event["event"] == "LOGIN_FAILED":
            ip = event["ip"]

            if ip not in failed_attempts:
                failed_attempts[ip] = 0

            failed_attempts[ip] += 1

    suspicious = {}

    for ip, attempts in failed_attempts.items():
        if attempts >= threshold:
            suspicious[ip] = attempts

    return suspicious


def generate_report(stats, suspicious):
    """Generate a human-readable security report."""
    report = []

    report.append("=" * 40)
    report.append("        SECURITY ANALYSIS")
    report.append("=" * 40)
    report.append("")
    report.append(f"Total events:       {stats['total']}")
    report.append(f"Failed logins:      {stats['failed']}")
    report.append(f"Successful logins:  {stats['successful']}")
    report.append("")

    report.append("Suspicious activity:")
    report.append("-" * 20)

    if not suspicious:
        report.append("No suspicious activity detected.")
    else:
        for ip, attempts in suspicious.items():
            report.append(f"{ip}")
            report.append(f"{attempts} failed login attempts")
            report.append("Possible brute-force activity detected.")
            report.append("")

    return "\n".join(report)


def main():
    filename = input("Enter log filename: ")

    try:
        logs = load_logs(filename)

        events = []

        for line in logs:
            try:
                events.append(parse_log(line))
            except ValueError:
                print(f"Warning: Skipping invalid log line: {line.strip()}")

        stats = analyze_events(events)

        suspicious = detect_suspicious_activity(events)

        report = generate_report(stats, suspicious)

        print()
        print(report)

    except FileNotFoundError:
        print("Error: Log file not found.")


if __name__ == "__main__":
    main()