"""Third-party integrations driven by the broker: Lark (notifications, approvals), Jira (one issue per
case) and 9router AI DECA (triage). Internally the AI integration is named `ai`; the API labels it 9router.

Data sources (generic webhook, syslog/CEF, Alibaba Cloud SLS) are configured the same way, per mode,
and tested by the broker, but run in the gateway (hypersoar.sources). The broker holds the master key
for every secret; the gateway gets it only to open data-source secrets, through views limited to them.
"""

from hypersoar import sources

OUTBOUND = ("lark", "jira", "ai")
NAMES = OUTBOUND + sources.NAMES
LABELS = {"lark": "Lark", "jira": "Jira", "ai": "9router AI DECA",
          **{n: s.label for n, s in sources.SPECS.items()}}
CATEGORY = {"lark": "notify", "jira": "ticketing", "ai": "ai", **{n: "source" for n in sources.NAMES}}
