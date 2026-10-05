import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { syntheticCredentialUrl } from "../fixtures/synthetic-credential-url.mjs";

// Kubeconfigs that the official Kubernetes client parses but whose identity or transport a
// Driver must refuse before contacting the API server: each differs from a safe kubeconfig
// (one token user, one verified-HTTPS cluster at the API root, one explicit context) in one
// way. Every API server is an unreachable loopback port, so an unrefused fixture fails late.
const context = "unsafe-fixture-context";
const scenarios = [
  { name: "unselected-context", context: "missing-context" },
  { name: "missing-credential-identity", users: [] },
  { name: "plaintext-api-endpoint", server: "http://127.0.0.1:1" },
  { name: "unverified-tls", skipTLSVerify: true },
  {
    name: "embedded-api-username",
    server: syntheticCredentialUrl({ username: "user", password: "", host: "127.0.0.1", port: 1 }),
  },
  {
    name: "embedded-api-password",
    server: syntheticCredentialUrl({
      username: "",
      password: "password",
      host: "127.0.0.1",
      port: 1,
    }),
  },
  { name: "unexpected-api-path", server: "https://127.0.0.1:1/untrusted" },
  { name: "api-query", server: "https://127.0.0.1:1/?untrusted=1" },
  { name: "api-fragment", server: "https://127.0.0.1:1/#untrusted" },
];

/**
 * Writes one kubeconfig per unsafe scenario into a private temporary directory that `t`
 * removes afterwards. Returns `{ name, kubeconfigPath, context }` per scenario, where
 * `context` is the context a Driver should be configured to request.
 */
export async function writeUnsafeKubeconfigs(t) {
  const directory = await mkdtemp(join(tmpdir(), "openclaw-unsafe-kubeconfig-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const written = [];
  for (const scenario of scenarios) {
    const kubeconfigPath = join(directory, `${scenario.name}.json`);
    await writeFile(
      kubeconfigPath,
      JSON.stringify({
        apiVersion: "v1",
        kind: "Config",
        clusters: [
          {
            name: "unsafe-fixture-cluster",
            cluster: {
              server: scenario.server ?? "https://127.0.0.1:1",
              ...(scenario.skipTLSVerify ? { "insecure-skip-tls-verify": true } : {}),
            },
          },
        ],
        users: scenario.users ?? [
          { name: "unsafe-fixture-user", user: { token: "test-only-fixture-token" } },
        ],
        contexts: [
          {
            name: context,
            context: { cluster: "unsafe-fixture-cluster", user: "unsafe-fixture-user" },
          },
        ],
        "current-context": context,
      }),
      { mode: 0o600 },
    );
    written.push({ name: scenario.name, kubeconfigPath, context: scenario.context ?? context });
  }
  return written;
}
