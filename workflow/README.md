# Workflow

Place your exported n8n workflow here as `waf-auto-alert-triage.json`.

## Before committing the file

1. In n8n, **unpin all data** on every node (pinned data is stored inside the export).
2. **Delete saved executions** for this workflow.
3. Export: workflow menu, then *Download*.
4. Open the JSON in a text editor and search for:
   - your real Google Sheet ID (replace it, or reselect the sheet after import)
   - real hostnames, domains, or IP prefixes
   - anything that looks like a key or token
5. Credentials are not included in n8n exports. After import, reselect them on the Google Sheets, AbuseIPDB, and Gemini nodes.
