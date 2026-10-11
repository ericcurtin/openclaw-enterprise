import assert from "node:assert/strict";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import {
  failureSecrets,
  maskPrivateKeyLines,
  redactOutputLine,
} from "../../scripts/ci/failure-redaction.mjs";

const protectedValues = new Set();

// The forms a registered value takes in logs and API errors besides itself:
// JSON-escaped (pino's JSON lines, and Go's, which also escapes <, > and &),
// base64 (a Secret's `data` in a kube API error) and percent-encoded. A value
// shorter than 8 characters gets no base64 forms, which would be short enough
// to garble unrelated text.
export function qaSecretVariants(value) {
  const json = JSON.stringify(value).slice(1, -1);
  const goJson = json.replace(
    /[<>&\u2028\u2029]/gu,
    (character) => `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
  const bytes = Buffer.from(value, "utf8");
  return [
    ...new Set([
      value,
      json,
      goJson,
      ...(value.length >= 8 ? [bytes.toString("base64"), bytes.toString("base64url")] : []),
      encodeURIComponent(value),
    ]),
  ];
}

export function registerQaSecret(value) {
  for (const variant of qaSecretVariants(value)) {
    protectedValues.add(variant);
  }
}

export function redactQaError(error) {
  // Longest first, so a value containing another is replaced whole.
  const secrets = [...protectedValues].sort((a, b) => b.length - a.length);
  for (const field of ["message", "stack"]) {
    if (typeof error[field] === "string") {
      for (const secret of secrets) {
        error[field] = error[field].replaceAll(secret, "[REDACTED]");
      }
    }
  }
  return error;
}

// Command arguments and stdout can contain API payloads. Publish only a bounded
// stderr tail, using the CI redactor plus dynamically generated fixture secrets.
export function qaCommandFailureDetail(stderr, env) {
  return redactedQaTail(stderr, env, { lines: 8, lineChars: 800 }).join("\n");
}

// The last `lines` lines of `text` (a command's stderr or a component log),
// each cut to `lineChars` after the same redaction: environment values, every
// registered fixture secret, common token shapes, and whole credential-bearing lines.
export function redactedQaTail(text, env, { lines, lineChars }) {
  const secrets = [
    ...failureSecrets([env]),
    // Text is redacted line by line, so each line of a multi-line value (a PEM
    // key) is a value of its own, as failureSecrets does for the environment.
    ...[...protectedValues].flatMap((value) => [
      [value, "qa-secret"],
      ...(value.includes("\n")
        ? value
            .split("\n")
            .map((line) => line.trim())
            .filter((line) => line.length >= 8)
            .map((line) => [line, "qa-secret"])
        : []),
    ]),
  ].sort(([a], [b]) => b.length - a.length);
  // A private key's body lines are found across the whole text, so a key that
  // starts above the tail still loses the lines inside it.
  return maskPrivateKeyLines(
    String(text ?? "")
      .trimEnd()
      .split("\n"),
  )
    .slice(-lines)
    .map((line) => redactOutputLine(line, secrets, "", lineChars));
}

export async function protectedText(path, label) {
  assert.ok(path, `${label} path is required`);
  // Check and read the same opened file; never follow a substituted symlink.
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat();
    assert.ok(
      info.isFile() && (info.mode & 0o077) === 0,
      `${label} must be a private regular file`,
    );
    const value = (await file.readFile("utf8")).trim();
    assert.ok(value.length > 0, `${label} must not be empty`);
    registerQaSecret(value);
    return value;
  } finally {
    await file.close();
  }
}

export async function grantQaSecret(f, agent, secretId, name) {
  const base = `/namespaces/${agent.namespaceId}`;
  const role = await f.api("POST", `${base}/iam/roles`, {
    name,
    permissions: [{ action: "operate", resourceKind: "secret" }],
  });
  await f.api("POST", `${base}/iam/access-bindings`, {
    subjectKind: "identity",
    subjectId: agent.servicePrincipalId,
    roleId: role.id,
    resourceKind: "secret",
    resourceId: secretId,
  });
}
