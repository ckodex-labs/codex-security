import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { basename, resolve } from "node:path";

const [archiveArg, evidenceArg = "../../artifacts/evidence"] =
  process.argv.slice(2);
if (archiveArg === undefined) {
  throw new Error("Usage: create-supply-chain-evidence.mjs <archive> [directory]");
}
const archive = resolve(archiveArg);
const evidenceDirectory = resolve(evidenceArg);
mkdirSync(evidenceDirectory, { recursive: true, mode: 0o700 });
const sbomPath = resolve(evidenceDirectory, "sbom.cyclonedx.json");
const result = spawnSync(
  process.env["SYFT_PATH"] ?? "syft",
  [
    "scan",
    `file:${archive}`,
    "--output",
    `cyclonedx-json=${sbomPath}`,
    "--source-name",
    basename(archive),
  ],
  {
    env: { PATH: process.env["PATH"], HOME: process.env["HOME"] },
    encoding: "utf8",
    maxBuffer: 1024 * 1024,
    timeout: 120_000,
  },
);
if (result.error !== undefined) throw result.error;
if (result.status !== 0) {
  throw new Error("Syft SBOM generation failed closed.");
}

const digest = (path) =>
  `sha256:${createHash("sha256").update(readFileSync(path)).digest("hex")}`;
const coveragePath = resolve(evidenceDirectory, "coverage.json");
const provenance = {
  _type: "https://in-toto.io/Statement/v1",
  predicateType: "https://slsa.dev/provenance/v1",
  subject: [{ name: basename(archive), digest: { sha256: digest(archive).slice(7) } }],
  predicate: {
    buildDefinition: {
      buildType: "urn:ckodex:build:npm-package:v1",
      externalParameters: {},
      internalParameters: {
        coverageDigest: digest(coveragePath),
        sbomDigest: digest(sbomPath),
      },
      resolvedDependencies: [],
    },
    runDetails: {
      builder: { id: "urn:ckodex:builder:dagger:0.21.7" },
      metadata: { invocationId: "local-reproducible" },
    },
  },
};
writeFileSync(
  resolve(evidenceDirectory, "provenance.intoto.json"),
  `${JSON.stringify(provenance)}\n`,
  { mode: 0o600 },
);
process.stdout.write(
  `${JSON.stringify({
    archiveDigest: digest(archive),
    coverageDigest: digest(coveragePath),
    sbomDigest: digest(sbomPath),
    provenanceDigest: digest(resolve(evidenceDirectory, "provenance.intoto.json")),
  })}\n`,
);
