// v1 — the approved version. The Deno twin of ../../v1_approved.lex.
//
// Run as approved:
//   deno run --allow-net=results.demo.internal v1_report.ts
//
// Deno's permission model is the closest thing in wide use to a
// capability grant: per-host network, per-path filesystem, per-variable
// environment, default-deny. Nothing below is a criticism of it.

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
