"""SOC console for the owner: alert feed, cases, approvals, kill switch, automation and the audit trail.
It reads the database as a member of deca_soar_viewer only. Every change is posted to the action broker,
which checks the role, the re-entered password and the policy and writes the audit trail."""
