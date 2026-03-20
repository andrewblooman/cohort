"""
shared – Reusable AWS query utilities for incident-response lambdas.

Provides common abstractions for querying CloudWatch Logs Insights and
CloudTrail so that enrichment logic can be shared across multiple Lambda
functions without duplication.

These utilities are deployed as a Lambda Layer and can be imported by any
Lambda in the incident-response workflow::

    from shared.cloudwatch_queries import run_insights_query
    from shared.cloudtrail_queries import lookup_cloudtrail_events
"""

__all__ = [
    "cloudwatch_queries",
    "cloudtrail_queries",
]
