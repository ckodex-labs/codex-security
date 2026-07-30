import { execFileSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { join } from "node:path";
import { tmpdir } from "node:os";

export interface TlsFixture {
  ca: Buffer;
  certificate: Buffer;
  privateKey: Buffer;
  clientCertificate: Buffer;
  clientPrivateKey: Buffer;
  fingerprint: `sha256:${string}`;
}

export function privateIpv4Address(): string | undefined {
  for (const entries of Object.values(networkInterfaces())) {
    for (const entry of entries ?? []) {
      if (
        entry.family === "IPv4" &&
        !entry.internal &&
        /^(?:10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/u.test(entry.address)
      ) {
        return entry.address;
      }
    }
  }
  return undefined;
}

export async function createTlsFixture(
  serverName = "model.internal",
): Promise<TlsFixture> {
  const directory = await mkdtemp(join(tmpdir(), "codex-security-tls-"));
  const configPath = join(directory, "server.cnf");
  const caKey = join(directory, "ca.key");
  const caCertificate = join(directory, "ca.pem");
  const serverKey = join(directory, "server.key");
  const request = join(directory, "server.csr");
  const certificate = join(directory, "server.pem");
  const clientKey = join(directory, "client.key");
  const clientRequest = join(directory, "client.csr");
  const clientCertificate = join(directory, "client.pem");
  await writeFile(
    configPath,
    [
      "[req]",
      "distinguished_name = dn",
      "req_extensions = extensions",
      "prompt = no",
      "[dn]",
      `CN = ${serverName}`,
      "[extensions]",
      `subjectAltName = DNS:${serverName}`,
      "extendedKeyUsage = serverAuth",
    ].join("\n"),
  );
  runOpenSsl(["genrsa", "-out", caKey, "2048"]);
  runOpenSsl([
    "req",
    "-x509",
    "-new",
    "-key",
    caKey,
    "-sha256",
    "-days",
    "1",
    "-subj",
    "/CN=Codex Security Test CA",
    "-out",
    caCertificate,
  ]);
  runOpenSsl(["genrsa", "-out", serverKey, "2048"]);
  runOpenSsl([
    "req",
    "-new",
    "-key",
    serverKey,
    "-out",
    request,
    "-config",
    configPath,
  ]);
  runOpenSsl(["genrsa", "-out", clientKey, "2048"]);
  runOpenSsl([
    "req",
    "-new",
    "-key",
    clientKey,
    "-out",
    clientRequest,
    "-subj",
    "/CN=codex-security-client",
  ]);
  runOpenSsl([
    "x509",
    "-req",
    "-in",
    clientRequest,
    "-CA",
    caCertificate,
    "-CAkey",
    caKey,
    "-CAcreateserial",
    "-out",
    clientCertificate,
    "-days",
    "1",
    "-sha256",
  ]);
  runOpenSsl([
    "x509",
    "-req",
    "-in",
    request,
    "-CA",
    caCertificate,
    "-CAkey",
    caKey,
    "-CAcreateserial",
    "-out",
    certificate,
    "-days",
    "1",
    "-sha256",
    "-extensions",
    "extensions",
    "-extfile",
    configPath,
  ]);
  const certificateBytes = await readFile(certificate);
  const fingerprint = new X509Certificate(certificateBytes).fingerprint256
    .replaceAll(":", "")
    .toLowerCase();
  return {
    ca: await readFile(caCertificate),
    certificate: certificateBytes,
    privateKey: await readFile(serverKey),
    clientCertificate: await readFile(clientCertificate),
    clientPrivateKey: await readFile(clientKey),
    fingerprint: `sha256:${fingerprint}`,
  };
}

function runOpenSsl(arguments_: readonly string[]): void {
  execFileSync("openssl", arguments_, { stdio: "ignore" });
}
