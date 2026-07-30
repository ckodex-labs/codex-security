import { spawnSync } from "node:child_process";

const evidenceMarkers = [
  "CKODEX_LIVE_DOCKER_VERIFIED",
  "CKODEX_LIVE_MODEL_PROCESS_VERIFIED",
];
const result = spawnSync(
  "bun",
  [
    "test",
    "--timeout",
    "30000",
    "./tests-ts/sandbox-docker-integration.test.ts",
    "./tests-ts/model-docker-process-live.test.ts",
  ],
  {
    encoding: "utf8",
    env: {
      ...process.env,
      CKODEX_LIVE_DOCKER: "1",
    },
    maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  },
);

process.stdout.write(result.stdout ?? "");
process.stderr.write(result.stderr ?? "");

if (result.error !== undefined) {
  throw result.error;
}
if (result.status !== 0) {
  process.exitCode = result.status ?? 1;
} else if (
  !evidenceMarkers.every((marker) =>
    (result.stdout ?? "").split(/\r?\n/u).includes(marker),
  )
) {
  process.stderr.write(
    "Live Docker sandbox test exited without its verification marker.\n",
  );
  process.exitCode = 1;
} else {
  process.stdout.write("live Docker sandbox verification: pass\n");
}
