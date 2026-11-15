
import re


def apply_risk_analysis(records):
    """Assign preliminary risk levels using simple rules."""

    for record in records:
        category = record.get("category")

        # Default for informational observations
        severity = "Informational"
        score = 0
        recommendation = "Review if this observation is relevant."

        # Network risk analysis
        if category == "Network":
            match = re.search(
                r"TCP port (\d+)",
                record.get("item", "")
            )

            port = int(match.group(1)) if match else None

            if port == 23:
                severity = "High"
                score = 4
                recommendation = (
                    "Verify whether Telnet is running. "
                    "If unnecessary, disable it."
                )

            elif port in {21, 135, 445, 3389}:
                severity = "Medium"
                score = 3
                recommendation = (
                    "Verify the service is required and "
                    "restrict access where appropriate."
                )

            else:
                severity = "Low"
                score = 1
                recommendation = (
                    "Verify the service and whether the port "
                    "needs to be accessible."
                )

        # File and Configuration observations
        elif category == "File/Config":
            severity = "Informational"
            score = 0
            recommendation = (
                "Inventory observation only. "
                "Manually review unfamiliar configuration "
                "and startup entries."
            )

        # Update record
        record["severity"] = severity
        record["risk_score"] = score
        record["recommendation"] = recommendation

    return records
