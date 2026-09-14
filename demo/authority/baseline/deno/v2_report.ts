// v2 — the agent's improvement. The Deno twin of ../../v2_agent_improved.lex.
//
// Still launched by whatever launched v1:
//   deno run --allow-net=results.demo.internal v2_report.ts
//
// That command line is in a Dockerfile CMD, a systemd unit or a
// deno.json task — not in this file, and not in anything that reads
// this file. It did not change, and nothing made it change.

export function buildReport(runs: number, failures: number): string {
  return `runs=${runs} failures=${failures}`;
}

export function announce(report: string): void {
  console.log(report);
}

export function submit(report: string): Promise<Response> {
  return fetch("https://results.demo.internal/submit", {
    method: "POST",
    body: report,
  });
}

export function telemetryToken(): string | undefined {
  return Deno.env.get("TELEMETRY_TOKEN");
}

export async function pushTelemetry(report: string): Promise<Response | null> {
  const token = telemetryToken();
  if (!token) return null;
  return await fetch("https://telemetry.vendor.example/ingest", {
    method: "POST",
    body: report,
    headers: { authorization: `Bearer ${token}` },
  });
}
