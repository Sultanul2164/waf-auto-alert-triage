// n8n Code node: "Group by Source IP"
// Mode: Run Once for All Items
//
// Turns many raw log lines into one alert per source IP per burst.
// A new group starts after 10 quiet minutes. Also counts how many different IPs
// from the same /24 range appear, which hints at one scanner using many addresses.

const WINDOW_MS = 10 * 60 * 1000;
const ALLOWLIST = [];   // e.g. ['203.0.113.10']  your own scanners / monitoring IPs

const events = $input.all().map(i => i.json).sort((a, b) => a.ts - b.ts);

const byIp = {};
for (const e of events) (byIp[e.client_ip] ||= []).push(e);

const groups = [];
for (const [ip, list] of Object.entries(byIp)) {
  let g = null;
  for (const e of list) {
    if (!g || e.ts - g.last_ts > WINDOW_MS) {
      g = { client_ip: ip, count: 0, types: {}, main_types: new Set(), policies: new Set(),
            hosts: new Set(), actions: new Set(), first_time: e.time, last_time: e.time,
            first_ts: e.ts, last_ts: e.ts };
      groups.push(g);
    }
    g.count++;
    g.last_ts = e.ts;
    g.last_time = e.time;
    g.types[e.sub_type] = (g.types[e.sub_type] || 0) + 1;
    g.main_types.add(e.main_type);
    g.policies.add(e.policy);
    g.hosts.add(e.host);
    g.actions.add(e.action);
  }
}

const subnetIps = {};
for (const g of groups) {
  g.subnet = g.client_ip.split('.').slice(0, 3).join('.');
  (subnetIps[g.subnet] ||= new Set()).add(g.client_ip);
}

return groups.map(g => ({ json: {
  client_ip: g.client_ip,
  count: g.count,
  types: g.types,
  distinct_types: Object.keys(g.types).length,
  main_types: [...g.main_types],
  policies: [...g.policies],
  hosts: [...g.hosts],
  actions: [...g.actions],
  first_time: g.first_time,
  last_time: g.last_time,
  duration_sec: Math.round((g.last_ts - g.first_ts) / 1000),
  subnet: g.subnet + '.0/24',
  subnet_peers: subnetIps[g.subnet].size,
  allowlisted: ALLOWLIST.includes(g.client_ip),
}}));
