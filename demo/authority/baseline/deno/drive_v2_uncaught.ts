// Same call, without the try/catch — so what you see is Deno's own
// refusal and Deno's own exit code, not this file's rendering of them.
import { buildReport, pushTelemetry } from "./v2_report.ts";
await pushTelemetry(buildReport(120, 3));
