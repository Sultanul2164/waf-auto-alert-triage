// n8n Code node: "Normalize Logs"
// Mode: Run Once for All Items
//
// Cleans each exported log row, skips blank rows, and works out which IP is the client.
// NOTE: in the FortiWeb CSV export used for this project, the Source and Destination
// columns were swapped compared with the GUI, so the public IP is treated as the client.

const isPrivate = ip => /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip);
const out = [];

for (const item of $input.all()) {
  const r = item.json;
  const src = String(r['Source'] ?? '').trim();
  const dst = String(r['Destination'] ?? '').trim();
  const time = String(r['Date/Time'] ?? '').trim();
  if (!src || !time) continue;                 // skip blank rows

  const client_ip = !isPrivate(src) ? src : (!isPrivate(dst) ? dst : src);
  const server_ip = client_ip === src ? dst : src;

  out.push({ json: {
    id: r['#'],
    time,
    ts: Date.parse(time.replace(' ', 'T')),
    action: r['Action'],
    policy: r['Policy'],
    client_ip,
    server_ip,
    host: r['HTTP Host'],
    url: r['URL'],
    main_type: r['Main Type'],
    sub_type: r['Sub Type'],
    threat_level: r['Threat Level'],
  }});
}
return out;
