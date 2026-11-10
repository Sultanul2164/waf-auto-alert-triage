// n8n Code node: "Score Alert"
// Mode: Run Once for Each Item
//
// Deterministic, explainable scoring. The AI never sets the score; it only explains it.

const { data, ...a } = $input.item.json;
const abuse = data?.abuseConfidenceScore ?? 0;

const TYPE_POINTS = {
  "Generic Attacks(Extended)": 35,
  "Information Disclosure": 30,
  "Illegal HTTP Version": 20,
  "Header Value Length Violation": 15,
  "HTTP Parsing Error": 10,
  "HTTP Duplicated Parameter Name": 10,
  "Missing POST Content Type": 5,
  "N/A": 10, // GEO IP policy hits
};
const HIGH_RISK =
  /sql|xss|cross.?site|scripting|injection|traversal|command|rce|shell|file.?inclusion/i;
let score = 0;
const reasons = [];

// 1. worst attack type in the group
let top = 0,
  topName = "";
for (const t of Object.keys(a.types)) {
  const p = HIGH_RISK.test(t) ? 50 : (TYPE_POINTS[t] ?? 15);
  if (p > top) {
    top = p;
    topName = t;
  }
}
score += top;
reasons.push(`worst type: ${topName} (+${top})`);

// 2. several different attack types from one IP
if (a.distinct_types > 1) {
  const p = (a.distinct_types - 1) * 5;
  score += p;
  reasons.push(`${a.distinct_types} different types (+${p})`);
}

// 3. volume
const vol = a.count >= 50 ? 25 : a.count >= 10 ? 15 : a.count >= 5 ? 10 : 0;
if (vol) {
  score += vol;
  reasons.push(`${a.count} events (+${vol})`);
}

// 4. coordinated range (several IPs from the same /24)
if (a.subnet_peers >= 3) {
  score += 15;
  reasons.push(`${a.subnet_peers} IPs from ${a.subnet} (+15)`);
}

// 5. IP reputation (AbuseIPDB)
if (abuse >= 80) {
  score += 40;
  reasons.push(`AbuseIPDB ${abuse}% (+40)`);
} else if (abuse >= 40) {
  score += 20;
  reasons.push(`AbuseIPDB ${abuse}% (+20)`);
}

// 6. production target
const prod = a.policies.some((p) => /prod/i.test(p));
if (prod) {
  score += 5;
  reasons.push("production policy (+5)");
}

score = Math.min(score, 100);
let level =
  score >= 70
    ? "high"
    : score >= 45
      ? "medium"
      : score >= 25
        ? "low"
        : "ignore";

// Severity floors: raise the level, never lower it
const rank = ["ignore", "low", "medium", "high"];
let floor = "ignore";
if (HIGH_RISK.test(topName)) floor = "medium";
if (a.main_types.includes("Signature Detection")) floor = "medium";
const unknown = Object.keys(a.types).filter(
  (t) => !(t in TYPE_POINTS) && !HIGH_RISK.test(t),
);
if (unknown.length) {
  floor = "medium";
  reasons.push(`unrecognized type: ${unknown.join(", ")} (escalated)`);
}
if (rank.indexOf(floor) > rank.indexOf(level)) {
  reasons.push(`severity floor: raised ${level} to ${floor}`);
  level = floor;
}

// Only what the AI needs. No hostnames, policy names, or internal IPs.
const llm_payload = {
  source_ip: a.client_ip,
  country: data?.countryCode ?? "unknown",
  isp: data?.isp ?? "unknown",
  abuseipdb_score: abuse,
  abuseipdb_total_reports: data?.totalReports ?? 0,
  events: a.count,
  window: `${a.first_time} to ${a.last_time}`,
  attack_types: a.types,
  waf_actions: a.actions,
  environment: prod ? "production" : "non-production",
  other_ips_in_same_subnet: a.subnet_peers - 1,
  score,
  rule_reasons: reasons,
};

return {
  json: {
    ...a,
    country: data?.countryCode,
    isp: data?.isp,
    abuse_score: abuse,
    score,
    level,
    reasons,
    llm_payload,
  },
};
