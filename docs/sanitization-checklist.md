# Sanitization checklist (before publishing a WAF project)

Changing IP addresses is not enough. Check every item below.

| Where | What it can reveal | Action |
|---|---|---|
| Policy names | Company or application names, environment | Replace with generic names such as `WEB_PROD_Policy` |
| HTTP Host values | Real hostnames, domains, public IP:port pairs | Replace with `app.example.com` |
| Internal IPs | Your network layout | Replace with `10.0.0.x` or documentation ranges |
| Ports | Real services | Replace or remove |
| Timestamps | When real traffic hit you | Shift all dates by a fixed offset |
| AbuseIPDB output (country, ISP, domain) | Tied to the real IPs | Re-run on fake IPs or edit the sample |
| Google Sheet ID and name | Embedded in the exported workflow JSON | Remove or point to a dummy sheet |
| Pinned data in n8n | Real data stored inside the export | Unpin all data before exporting |
| Saved executions | Real data in run history | Delete executions before exporting |
| Screenshots | Everything above, shown on screen | Check every pixel, including AI summary text |
| Git history | Anything ever committed | Start the repo clean; deleting later does not remove history |

## Final checks

1. Open the exported workflow JSON in a text editor and search for your real IP prefixes, domain name, and sheet ID.
2. Search the whole repo for fragments of your real data (first two octets, company name, hostnames).
3. Confirm no API keys appear anywhere (n8n exports omit credentials, but check anyway).
4. Get permission from your employer before sharing anything derived from production logs.

## Safe reserved IP ranges for demos

| Range | Name |
|---|---|
| 192.0.2.0/24 | TEST-NET-1 |
| 198.51.100.0/24 | TEST-NET-2 |
| 203.0.113.0/24 | TEST-NET-3 |
| 10.0.0.0/8 | Private (internal examples) |
