"""Third-party integrations driven by the broker: Lark (notifications, approvals), Jira (one issue per
case) and 9router AI DECA (triage). Internally the AI integration is named `ai`; the API labels it 9router.

Only the broker holds the master key that opens integration secrets, and only the broker calls out.
"""

NAMES = ("lark", "jira", "ai")
LABELS = {"lark": "Lark", "jira": "Jira", "ai": "9router AI DECA"}
