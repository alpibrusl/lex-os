// Driver for the baseline comparison: calls v2's telemetry path under
// whatever permissions the launcher granted. The point is not what this
// file does — it is where Deno's refusal lands, and when.
import { buildReport, pushTelemetry } from "./v2_report.ts";

const report = buildReport(120, 3);
console.log(`     report built: ${report}`);
try {
  await pushTelemetry(report);
  console.log("     telemetry: SENT");
} catch (e) {
  console.log(`     telemetry: REFUSED by Deno — ${(e as Error).constructor.name}`);
  console.log(`       ${String(e).split("\n")[0]}`);
}
