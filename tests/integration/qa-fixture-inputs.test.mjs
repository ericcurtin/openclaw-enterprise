import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { chmod, mkdtemp, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { protectedText } from "../helpers/qa-secrets.mjs";

test("QA credentials require a private regular file and reject symlink substitution", async (t) => {
  const directory = await mkdtemp(join(tmpdir(), "qa-credential-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const credential = join(directory, "credential");
  await writeFile(credential, " test-only-credential\n", { mode: 0o600 });
  assert.equal(await protectedText(credential, "test credential"), "test-only-credential");

  // A path replaced with a symlink must not redirect the credential read,
  // even when its target would pass the regular-file and permission checks.
  const link = join(directory, "substituted");
  await symlink(credential, link);
  await assert.rejects(protectedText(link, "test credential"), { code: "ELOOP" });
  await assert.rejects(protectedText(directory, "test credential"), /private regular file/);
  await chmod(credential, 0o644);
  await assert.rejects(protectedText(credential, "test credential"), /private regular file/);
  await chmod(credential, 0o600);
  await writeFile(credential, " \n");
  await assert.rejects(protectedText(credential, "test credential"), /must not be empty/);
});

test(
  "parallel QA stages publish complete outcomes, failures and timings",
  { timeout: 30_000 },
  async (t) => {
    const directory = await mkdtemp(join(tmpdir(), "qa-report-"));
    t.after(() => rm(directory, { recursive: true, force: true }));
    const output = join(directory, "matrix.json");
    const reportModule = new URL("../helpers/qa-report.mjs", import.meta.url).href;
    // Exercise the real reporter under node:test, including failed subtests.
    // A shared writeFile without a serialized snapshot can lose concurrent rows
    // or leave a trailing fragment of the previous JSON document.
    const source = `
    import test from 'node:test';
    import { createQaReport } from ${JSON.stringify(reportModule)};
    const report = createQaReport(${JSON.stringify(output)}, { scope: 'full', concurrency: 4 });
    test('parallel report', { concurrency: 4 }, async (t) => {
      await Promise.all(Array.from({length: 20}, (_, i) =>
        report.stage(t, 'compose/Codex', 'stage-' + i, async () => {
          if (i === 2) throw new Error('blocked by unavailable test prerequisite');
          if (i === 7) throw new Error('expected assertion failure');
        }, 'scenario-' + i)
      ));
      await report.save();
    });
  `;
    const child = spawn(process.execPath, ["--input-type=module", "-e", source], {
      stdio: ["ignore", "pipe", "pipe"],
    });
    t.after(() => {
      if (child.exitCode === null) {
        child.kill("SIGKILL");
      }
    });
    let diagnostic = "";
    for (const stream of [child.stdout, child.stderr]) {
      stream.on("data", (chunk) => {
        diagnostic += chunk;
      });
    }
    const code = await new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", resolve);
    });
    assert.equal(code, 1, diagnostic);
    const report = JSON.parse(await readFile(output, "utf8"));
    assert.equal(report.scope, "full");
    assert.equal(report.concurrency, 4);
    assert.equal(report.outcomes.length, 20);
    assert.equal(new Set(report.outcomes.map((row) => row.scenario)).size, 20);
    for (let i = 0; i < 20; i += 1) {
      const row = report.outcomes.find((value) => value.stage === `stage-${i}`);
      assert.equal(row.cell, "compose/Codex");
      assert.equal(row.scenario, `scenario-${i}`);
      let expectedOutcome = "passed";
      if (i === 2) {
        expectedOutcome = "blocked";
      } else if (i === 7) {
        expectedOutcome = "failed";
      }
      assert.equal(row.outcome, expectedOutcome);
      assert.ok(Number.isFinite(Date.parse(row.startedAt)));
      assert.ok(Number.isInteger(row.durationMs) && row.durationMs >= 0);
    }
    assert.match(report.outcomes.find((row) => row.stage === "stage-2").reason, /blocked by/);
    assert.match(
      report.outcomes.find((row) => row.stage === "stage-7").reason,
      /expected assertion/,
    );
    assert.equal((await stat(output)).mode & 0o777, 0o600);
    assert.deepEqual(await readdir(directory), ["matrix.json"]);
  },
);

test("QA selection keeps prerequisite credentials and reports omitted coverage", async () => {
  const { selectQaMatrix, validateQaInputs } = await import("../helpers/qa-selection.mjs");
  const selected = selectQaMatrix({ OCC_TEST_QA_SCENARIOS: "model-ui,calendar" });
  assert.equal(selected.scope, "partial:selected");
  assert.deepEqual(
    selected.cells.map(({ cell, scenarios }) => ({ cell, scenarios })),
    [
      { cell: "compose/OpenClaw", scenarios: ["model-ui"] },
      { cell: "compose/Codex", scenarios: ["model-ui", "calendar"] },
      { cell: "kubernetes/OpenClaw", scenarios: ["model-ui"] },
      { cell: "kubernetes/Codex", scenarios: ["model-ui", "calendar"] },
    ],
  );
  assert.deepEqual(selected.cells[1].unselected, ["git-full", "git-read", "slack"]);
  assert.deepEqual(selected.cells[0].notApplicable, ["calendar", "git-read", "slack"]);
  assert.throws(() => validateQaInputs(selected, {}), /OPENAI_KEY_FILE is required/);
  assert.throws(
    () => selectQaMatrix({ OCC_TEST_QA_SCENARIOS: "model-ui,typo" }),
    /invalid QA scenario/,
  );
  assert.throws(() => selectQaMatrix({ OCC_TEST_QA_SCENARIOS: "" }), /invalid QA scenario/);
  assert.throws(
    () => selectQaMatrix({ OCC_TEST_QA_SCENARIOS: "calendar", OCC_TEST_QA_PRESET: "OpenClaw" }),
    /not applicable/,
  );
  const calendar = selectQaMatrix({
    OCC_TEST_QA_SCENARIOS: "calendar",
    OCC_TEST_QA_INSTALLATION: "compose",
  });
  assert.ok(!calendar.requiredEnv.includes("OCC_TEST_QA_OPENAI_KEY_FILE"));
  assert.deepEqual(calendar.cells[0].scenarios, []);
  const openclaw = selectQaMatrix({ OCC_TEST_QA_PRESET: "OpenClaw" });
  assert.deepEqual(openclaw.cells[0].scenarios, ["model-ui", "git-full"]);
  assert.ok(!openclaw.requiredEnv.some((name) => /CODEX|SLACK|CALENDAR/.test(name)));
  const full = selectQaMatrix({});
  assert.equal(full.scope, "full");
  assert.ok(full.repository);
  assert.throws(
    () =>
      validateQaInputs(full, Object.fromEntries(full.requiredEnv.map((name) => [name, "fixture"]))),
    /explicit authorization/,
  );
});

test("hosted QA materializes only selected credentials and rejects missing selected inputs", async (t) => {
  const { spawnSync } = await import("node:child_process");
  const script = new URL("../../scripts/ci/qa-matrix-credentials.mjs", import.meta.url);
  const directory = await mkdtemp(join(tmpdir(), "qa-hosted-inputs-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const githubEnv = join(directory, "github-env");
  const result = spawnSync(process.execPath, [script.pathname], {
    encoding: "utf8",
    env: {
      RUNNER_TEMP: directory,
      GITHUB_ENV: githubEnv,
      OCC_TEST_QA_SCENARIOS: "model-ui,calendar",
      OPENAI_API_KEY: "synthetic-model-key",
      CODEX_ACCESS_TOKEN: "synthetic-codex-token",
      OCC_TEST_CODEX_CALENDAR_TOOL_NAME: "test.calendar.read",
      OCC_TEST_CODEX_CALENDAR_RESULT_EXPECT: "email",
      // Even if a caller supplies unrelated credentials, do not write them.
      SLACK_APP_TOKEN: "unselected-secret",
      REPOSITORY_APP_KEY: "unselected-secret",
    },
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout + result.stderr, "");
  const privateDirectory = join(directory, "qa-matrix-credentials");
  assert.deepEqual((await readdir(privateDirectory)).sort(), ["codex", "openai"]);
  assert.equal(
    await protectedText(join(privateDirectory, "codex"), "Codex credential"),
    "synthetic-codex-token",
  );
  const exported = await readFile(githubEnv, "utf8");
  assert.match(exported, /OCC_TEST_QA_CODEX_TOKEN_FILE=/);
  assert.doesNotMatch(exported, /synthetic-|unselected-secret|SLACK|REPOSITORY/);
  await rm(privateDirectory, { recursive: true });
  await rm(githubEnv);
  const missing = spawnSync(process.execPath, [script.pathname], {
    encoding: "utf8",
    env: {
      RUNNER_TEMP: directory,
      GITHUB_ENV: githubEnv,
      OCC_TEST_QA_SCENARIOS: "calendar",
      CODEX_ACCESS_TOKEN: "synthetic-codex-token",
      OCC_TEST_CODEX_CALENDAR_RESULT_EXPECT: "email",
    },
  });
  assert.notEqual(missing.status, 0);
  assert.match(missing.stderr, /CALENDAR_TOOL_NAME is required/);
  await assert.rejects(readFile(githubEnv), { code: "ENOENT" });
});

test("QA command diagnostics retain the error while hiding generated and environment secrets", async () => {
  const { qaCommandFailureDetail, registerQaSecret } = await import("../helpers/qa-secrets.mjs");
  registerQaSecret("generated-private-value");
  const output = qaCommandFailureDetail(
    "earlier detail\n".repeat(12) +
      "Docker service could not start: generated-private-value and process-private-value\nAuthorization: Bearer example-private-value\n",
    { PRIVATE_INPUT: "process-private-value" },
  );
  assert.match(output, /Docker service could not start/);
  assert.ok(output.split("\n").length <= 8);
  assert.doesNotMatch(
    output,
    /generated-private-value|process-private-value|example-private-value/,
  );
});

test("QA waits report the last observation when they time out", async () => {
  const { waitFor } = await import("../helpers/qa-utils.mjs");
  let observations = 0;
  let last;
  await assert.rejects(
    waitFor(
      "fake condition",
      async () => {
        observations += 1;
        last = { observation: observations, pods: ["runtime-0"] };
        return false;
      },
      200,
      { describe: () => JSON.stringify(last), interval: 5 },
    ),
    (error) => {
      assert.equal(
        error.message,
        `Timed out: fake condition; last observation: {"observation":${observations},"pods":["runtime-0"]}`,
      );
      return true;
    },
  );
  assert.ok(observations >= 2, "the wait observed more than once");
  // Without `describe` the message is unchanged; a failing `describe` keeps the timeout.
  await assert.rejects(
    waitFor("plain condition", async () => false, 10, { interval: 5 }),
    (error) => error.message === "Timed out: plain condition",
  );
  await assert.rejects(
    waitFor("broken describe", async () => false, 10, {
      interval: 5,
      describe: () => {
        throw new Error("no state");
      },
    }),
    (error) =>
      error.message === "Timed out: broken describe; last observation unavailable (no state)",
  );
  assert.equal(
    await waitFor("ready", async () => "value", 10, { describe: () => "unused" }),
    "value",
  );
});

test("a QA Agent stop timeout names the remaining Pods and keeps redacted platform logs", async () => {
  const { registerQaSecret } = await import("../helpers/qa-secrets.mjs");
  const { stopQaAgent, describeStopObservation } = await import("../helpers/qa-repository.mjs");
  registerQaSecret("stop-fixture-service-key");
  const agent = { id: "agent-1", namespaceId: "namespace-1" };
  const pod = {
    metadata: {
      namespace: "oce-agent-1",
      name: "agent-1-gateway-0",
      deletionTimestamp: "2026-10-11T01:37:00Z",
      finalizers: ["openclaw.dev/runtime"],
      labels: { "openclaw.dev/agent": "agent-1", "openclaw.dev/workload-role": "gateway" },
    },
    spec: { containers: [{ env: [{ name: "GATEWAY_PASSWORD", value: "spec-private-value" }] }] },
    status: { phase: "Running" },
  };
  // A remaining Agent Pod whose log is not read, in the platform Namespace for the
  // Events de-duplication.
  const agentPod = {
    metadata: {
      namespace: "oce-system",
      name: "agent-1-runtime-0",
      labels: { "openclaw.dev/agent": "agent-1", "openclaw.dev/workload-role": "agent" },
    },
    status: { phase: "Running" },
  };
  // A rollout: two worker Pods, one restarted, and an API Pod.
  const platformPods = [
    {
      metadata: { name: "worker-a", labels: { "app.kubernetes.io/component": "worker" } },
      spec: { containers: [{ env: [{ name: "DATABASE_URL", value: "spec-private-value" }] }] },
      status: {
        phase: "Running",
        startTime: "2026-10-11T01:30:00Z",
        containerStatuses: [
          {
            name: "worker",
            restartCount: 1,
            lastState: {
              terminated: { reason: "Error", exitCode: 1, finishedAt: "2026-10-11T01:33:00Z" },
            },
          },
        ],
      },
    },
    {
      metadata: { name: "worker-b", labels: { "app.kubernetes.io/component": "worker" } },
      status: { phase: "Running", containerStatuses: [{ name: "worker", restartCount: 0 }] },
    },
    { metadata: { name: "api-a", labels: { "app.kubernetes.io/component": "api" } }, status: {} },
  ];
  const event = (time, name, message) => ({
    lastTimestamp: time,
    type: "Normal",
    reason: "Killing",
    involvedObject: { kind: "Pod", name },
    message,
  });
  const calls = [];
  const records = new Map();
  const f = {
    controlPlane: "kubernetes",
    env: {
      PRIVATE_INPUT: "launcher-private-value",
      OCC_DEVELOPMENT_COMPUTE_DRIVER: "kubernetes",
      OCC_DEVELOPMENT_COMPOSE_PROJECT: "occ-dev-qa-k-ab12cd34",
      OCC_DEVELOPMENT_KUBERNETES_CLUSTER: "occ-dev-qa-k-ab12cd34",
      OCC_DEVELOPMENT_STATE_DIRECTORY: "/runner/tmp/occ-dev-qa-k-ab12cd34-x/state",
      OCC_DEVELOPMENT_K3S_IMAGE: "docker.io/rancher/k3s:v1.35.9-k3s1",
    },
    state: { platformNamespace: "oce-system" },
    async api(method, path) {
      calls.push(["api", method, path]);
      return method === "GET"
        ? { desiredRuntimeState: "stopped", activeRevisionId: "revision-1" }
        : undefined;
    },
    async kubectl(...args) {
      calls.push(["kubectl", ...args]);
      if (args[0] === "get") {
        return JSON.stringify({ items: [pod, agentPod] });
      }
      if (args.includes("deployment/openclaw-enterprise-worker")) {
        throw new Error("kubectl failed (exit 1); stderr: launcher-private-value unreachable");
      }
      const [verb, target] = args.slice(2);
      if (verb === "get" && target === "pods") {
        return JSON.stringify({ items: platformPods });
      }
      if (verb === "get" && target === "events") {
        return JSON.stringify({
          items: [
            event("2026-10-11T01:36:30Z", "agent-1-gateway-0", "Stopping; launcher-private-value"),
            event(undefined, "undated", "no time"),
            event("2026-10-11T01:30:00Z", "worker-a", "Started container worker"),
          ],
        });
      }
      if (args.includes("--previous")) {
        throw new Error("kubectl failed (exit 1); stderr: previous launcher-private-value gone");
      }
      if (target === "worker-a" || target === "worker-b") {
        return `2026-10-11T01:36:00Z ${target} worker.completed\n`;
      }
      if (target === "agent-1-gateway-0") {
        return (
          "2026-10-11T01:32:40Z draining active work before stop with timeout 315000ms: 1 active chat run(s)\n" +
          "2026-10-11T01:32:41Z assistant reply QA_NATIVE_conversation-text: drain the shutdown queue\n"
        );
      }
      return (
        "2026-10-11T01:36:00Z kubernetes compute: stop requested for agent-1\n" +
        "2026-10-11T01:36:01Z authenticated with stop-fixture-service-key\n" +
        "2026-10-11T01:36:02Z Authorization: Bearer abcdefghijklmnop\n" +
        "2026-10-11T01:36:03Z cluster occ-dev-qa-k-ab12cd34 state /runner/tmp/occ-dev-qa-k-ab12cd34-x/state image docker.io/rancher/k3s:v1.35.9-k3s1\n"
      );
    },
    async record(name, value) {
      records.set(name, value);
      return `${this.controlPlane}-${name}.json`;
    },
  };
  await assert.rejects(stopQaAgent(f, agent, { timeout: 10 }), (error) => {
    assert.match(error.message, /^Timed out: ordinary Agent stop removes every runtime Pod; /);
    const observation = JSON.parse(
      /; last observation: (\{.*\}); API and worker logs: /.exec(error.message)[1],
    );
    assert.deepEqual(observation, {
      desiredRuntimeState: "stopped",
      activeRevisionId: "revision-1",
      pods: [
        {
          namespace: "oce-agent-1",
          name: "agent-1-gateway-0",
          phase: "Running",
          deletionTimestamp: "2026-10-11T01:37:00Z",
          finalizers: ["openclaw.dev/runtime"],
        },
        {
          namespace: "oce-system",
          name: "agent-1-runtime-0",
          phase: "Running",
          deletionTimestamp: null,
          finalizers: [],
        },
      ],
    });
    assert.match(
      error.message,
      /API and worker logs: kubernetes-agent-1-stop-timeout-platform-logs\.json$/,
    );
    assert.doesNotMatch(error.message, /spec-private-value/);
    return true;
  });
  assert.equal(agent.stopped, undefined);
  assert.deepEqual(calls[0], ["api", "POST", "/namespaces/namespace-1/agents/agent-1/stop"]);
  const logCall = calls.find((call) => call.includes("deployment/openclaw-enterprise-api"));
  assert.deepEqual(logCall.slice(1, 7), [
    "-n",
    "oce-system",
    "logs",
    "deployment/openclaw-enterprise-api",
    "--container",
    "api",
  ]);
  assert.ok(
    logCall.some((argument) => /^--tail=\d+$/.test(argument)),
    "the log tail is bounded",
  );
  const { logs } = records.get("agent-1-stop-timeout-platform-logs");
  assert.equal(logs.api[0], "2026-10-11T01:36:00Z kubernetes compute: stop requested for agent-1");
  assert.doesNotMatch(
    JSON.stringify(logs),
    /stop-fixture-service-key|abcdefghijklmnop|launcher-private-value/,
  );
  assert.equal(logs.api.length, 4);
  // Fixed launcher settings stay readable.
  assert.equal(
    logs.api[3],
    "2026-10-11T01:36:03Z cluster occ-dev-qa-k-ab12cd34 state /runner/tmp/occ-dev-qa-k-ab12cd34-x/state image docker.io/rancher/k3s:v1.35.9-k3s1",
  );
  assert.match(logs.worker.unavailable.join("\n"), /unreachable/);
  assert.equal(describeStopObservation(undefined), "none");
  // During a rollout every worker Pod by name; only a restarted one's previous
  // container, whose failed read is kept, redacted.
  assert.deepEqual(logs.workerPods, {
    "worker-a": ["2026-10-11T01:36:00Z worker-a worker.completed"],
    "worker-b": ["2026-10-11T01:36:00Z worker-b worker.completed"],
  });
  assert.deepEqual(
    calls.filter((call) => call.includes("--previous")).map((call) => call.slice(1)),
    [
      [
        "-n",
        "oce-system",
        "logs",
        "worker-a",
        "--container",
        "worker",
        "--previous",
        "--timestamps",
        "--tail=200",
        "--request-timeout=30s",
      ],
    ],
  );
  assert.match(logs.workerPrevious["worker-a"].unavailable.join("\n"), /gone/);
  assert.deepEqual(logs.platformPods[0], {
    name: "worker-a",
    component: "worker",
    phase: "Running",
    startTime: "2026-10-11T01:30:00Z",
    deletionTimestamp: null,
    containers: [
      {
        name: "worker",
        restartCount: 1,
        lastTerminated: { reason: "Error", exitCode: 1, finishedAt: "2026-10-11T01:33:00Z" },
      },
    ],
  });
  // Events from the platform and each other remaining Namespace, oldest first.
  assert.deepEqual(Object.keys(logs.events), ["oce-system", "oce-agent-1"]);
  assert.equal(calls.filter((call) => call.includes("events")).length, 2);
  assert.deepEqual(
    logs.events["oce-agent-1"].map(({ object }) => object),
    ["Pod/undated", "Pod/worker-a", "Pod/agent-1-gateway-0"],
  );
  // Only a remaining Gateway Pod's own drain messages; the Agent Pod's log is not read.
  assert.deepEqual(logs.gatewayDrain, {
    "agent-1-gateway-0": [
      "2026-10-11T01:32:40Z draining active work before stop with timeout 315000ms: 1 active chat run(s)",
    ],
  });
  assert.ok(!calls.some((call) => call.includes("agent-1-runtime-0")));
  assert.deepEqual(calls.find((call) => call.includes("agent-1-gateway-0")).slice(1, 7), [
    "-n",
    "oce-agent-1",
    "logs",
    "agent-1-gateway-0",
    "--container",
    "gateway",
  ]);
  assert.doesNotMatch(
    JSON.stringify(logs),
    /spec-private-value|QA_NATIVE_conversation-text|launcher-private-value/,
  );
  // A single worker Pod is the Deployment read: no per-Pod copies.
  platformPods.splice(0, 1);
  await assert.rejects(
    stopQaAgent(f, { id: "agent-3", namespaceId: "namespace-1" }, { timeout: 10 }),
  );
  assert.equal(records.get("agent-3-stop-timeout-platform-logs").logs.workerPods, undefined);

  // A Compose control plane keeps the observation but has no in-cluster platform logs.
  records.clear();
  const composeAgent = { id: "agent-2", namespaceId: "namespace-1" };
  await assert.rejects(
    stopQaAgent({ ...f, controlPlane: "compose" }, composeAgent, { timeout: 10 }),
    (error) =>
      /; last observation: \{.*"pods":\[\{/.test(error.message) &&
      !/API and worker logs/.test(error.message),
  );
  assert.equal(records.size, 0);
});

test("a QA Agent stop waits for the Gateway stop bound and records a slow stop without failing", async (t) => {
  const { GATEWAY_STOP_TIMEOUT_MS } =
    await import("../../apps/controller/src/drivers/compute/kubernetes/runtime-entrypoints.ts");
  const { stopQaAgent, QA_STOP_TIMEOUT_MS, QA_SLOW_STOP_MS } =
    await import("../helpers/qa-repository.mjs");
  // The worker's own Gateway wait (grace plus one request) fits, with room for the
  // Harness and the API; the old 300 s default did not.
  assert.ok(QA_STOP_TIMEOUT_MS >= GATEWAY_STOP_TIMEOUT_MS + 10_000 + 3 * 60_000);
  assert.ok(QA_STOP_TIMEOUT_MS > 300_000);
  assert.equal(QA_SLOW_STOP_MS, 60_000);

  const gateway = {
    metadata: {
      namespace: "oce-agent-4",
      name: "agent-4-gateway-0",
      deletionTimestamp: "2026-10-11T07:23:42Z",
      labels: { "openclaw.dev/agent": "agent-4", "openclaw.dev/workload-role": "gateway" },
    },
    status: { phase: "Running" },
  };
  let clock = 0;
  // Each GET advances the clock by the next step; the last step's read finds the stop done.
  const fixture = (steps, { done = true } = {}) => {
    const records = new Map();
    let reads = 0;
    const finished = () => done && reads >= steps.length;
    const f = {
      controlPlane: "kubernetes",
      env: { PRIVATE_INPUT: "launcher-private-value" },
      state: { platformNamespace: "oce-system" },
      async api(method) {
        if (method !== "GET") {
          return undefined;
        }
        clock += steps[Math.min(reads, steps.length - 1)];
        reads += 1;
        return finished()
          ? { desiredRuntimeState: "stopped", activeRevisionId: null }
          : { desiredRuntimeState: "stopped", activeRevisionId: "revision-4" };
      },
      async kubectl(...args) {
        if (args[0] === "get") {
          return JSON.stringify({ items: finished() ? [] : [gateway] });
        }
        const [verb, target] = args.slice(2);
        if (verb === "get") {
          return JSON.stringify({ items: [] });
        }
        if (target === "agent-4-gateway-0") {
          return "2026-10-11T07:18:13Z draining active work before stop with timeout 315000ms: 1 active chat run(s)\n";
        }
        return "2026-10-11T07:18:12Z worker.completed\n";
      },
      // Like the QA fixture's record: exclusive creation.
      async record(name, value) {
        if (records.has(name)) {
          throw new Error(`EEXIST: ${name}`);
        }
        records.set(name, value);
        return `${this.controlPlane}-${name}.json`;
      },
    };
    return { f, records };
  };
  const written = [];
  t.mock.method(process.stderr, "write", (text) => {
    written.push(String(text));
    return true;
  });
  const drain = [
    "2026-10-11T07:18:13Z draining active work before stop with timeout 315000ms: 1 active chat run(s)",
  ];

  // A fast stop leaves no evidence.
  const fast = fixture([0, 5_000]);
  const fastAgent = { id: "agent-4", namespaceId: "namespace-1" };
  await stopQaAgent(fast.f, fastAgent, { now: () => clock });
  assert.equal(fastAgent.stopped, true);
  assert.equal(fast.records.size, 0);
  assert.deepEqual(written, []);

  // Still running past 60 s: the drain lines are captured once, while the Gateway
  // drains, then the completed stop records its total time and passes.
  clock = 0;
  const slow = fixture([61_000, 1_000, 1_000, 200_000]);
  const slowAgent = { id: "agent-4", namespaceId: "namespace-1" };
  await stopQaAgent(slow.f, slowAgent, { now: () => clock });
  assert.equal(slowAgent.stopped, true);
  assert.deepEqual([...slow.records.keys()].sort(), [
    "agent-4-slow-stop",
    "agent-4-slow-stop-platform-logs",
  ]);
  assert.deepEqual(
    slow.records.get("agent-4-slow-stop-platform-logs").logs.gatewayDrain["agent-4-gateway-0"],
    drain,
  );
  assert.deepEqual(slow.records.get("agent-4-slow-stop"), {
    thresholdMs: 60_000,
    observedAfterMs: 61_000,
    observation: {
      desiredRuntimeState: "stopped",
      activeRevisionId: "revision-4",
      pods: [
        {
          namespace: "oce-agent-4",
          name: "agent-4-gateway-0",
          phase: "Running",
          deletionTimestamp: "2026-10-11T07:23:42Z",
          finalizers: [],
        },
      ],
    },
    platformLogs: "kubernetes-agent-4-slow-stop-platform-logs.json",
    elapsedMs: 263_000,
  });
  assert.equal(written.length, 1);
  assert.match(
    written[0],
    /^QA slow stop \(diagnostic, not a failure\): Agent agent-4 took 263 s; drain evidence: kubernetes-agent-4-slow-stop-platform-logs\.json\n$/,
  );

  // A stop that first finishes after 60 s still records its time, without a capture.
  // Stopping the same Agent again gets its own evidence names.
  clock = 0;
  const late = fixture([61_000]);
  await stopQaAgent(late.f, slowAgent, { now: () => clock });
  assert.deepEqual(late.records.get("agent-4-2-slow-stop"), {
    thresholdMs: 60_000,
    elapsedMs: 61_000,
  });
  assert.match(written[1], /took 61 s\n$/);

  // Evidence that cannot be written never fails a completed stop, and its error is redacted.
  clock = 0;
  const unwritable = fixture([61_000, 1_000]);
  const failures = [];
  unwritable.f.record = async (name) => {
    failures.push(name);
    throw new Error("EEXIST: launcher-private-value exists");
  };
  const unwritableAgent = { id: "agent-4", namespaceId: "namespace-1" };
  await stopQaAgent(unwritable.f, unwritableAgent, { now: () => clock });
  assert.equal(unwritableAgent.stopped, true);
  assert.deepEqual(failures, ["agent-4-slow-stop-platform-logs", "agent-4-slow-stop"]);
  assert.match(written[2], /took 62 s\n$/);

  // A slow stop that then times out names the drain evidence captured while it ran;
  // it records no completed-stop summary.
  const stuck = fixture([1_000], { done: false });
  const stuckAgent = { id: "agent-5", namespaceId: "namespace-1" };
  await assert.rejects(
    stopQaAgent(stuck.f, stuckAgent, { slowAfter: 0, timeout: 10, now: () => clock }),
    (error) => {
      assert.match(
        error.message,
        /; API and worker logs: kubernetes-agent-5-stop-timeout-platform-logs\.json; drain evidence after \d+ s: kubernetes-agent-5-slow-stop-platform-logs\.json$/,
      );
      return true;
    },
  );
  assert.equal(stuckAgent.stopped, undefined);
  assert.deepEqual([...stuck.records.keys()].sort(), [
    "agent-5-slow-stop-platform-logs",
    "agent-5-stop-timeout-platform-logs",
  ]);
  assert.equal(written.length, 3);
});

test("QA log redaction hides each line of a registered multi-line secret", async () => {
  const { redactedQaTail, registerQaSecret } = await import("../helpers/qa-secrets.mjs");
  const body = ["MIIEfixtureLineOneAAAAAAAA", "fixtureLineTwoBBBBBBBBBBBB"];
  registerQaSecret(
    ["-----BEGIN PRIVATE KEY-----", ...body, "-----END PRIVATE KEY-----"].join("\n"),
  );
  const lines = redactedQaTail(
    `reading key\n${body[0]}\n${body[1]}\ndone\n`,
    {},
    {
      lines: 10,
      lineChars: 200,
    },
  );
  assert.deepEqual(lines[0], "reading key");
  assert.equal(lines.at(-1), "done");
  assert.doesNotMatch(lines.join("\n"), /fixtureLine/);
});

test("QA log redaction hides JSON-escaped, base64 and percent-encoded copies of a registered secret", async () => {
  const { redactQaError, redactedQaTail, registerQaSecret } =
    await import("../helpers/qa-secrets.mjs");
  // Synthetic, with every character an encoding changes.
  const value = 'synthetic"qa\\value/<&>+= 2026';
  registerQaSecret(value);
  const json = JSON.stringify(value).slice(1, -1);
  const encoded = [
    json,
    // Go's encoding/json (kube API errors) also escapes <, > and &.
    json.replaceAll("<", "\\u003c").replaceAll(">", "\\u003e").replaceAll("&", "\\u0026"),
    Buffer.from(value).toString("base64"),
    Buffer.from(value).toString("base64url"),
    encodeURIComponent(value),
  ];
  assert.equal(new Set([value, ...encoded]).size, 6);
  const text = [
    `plain ${value}`,
    JSON.stringify({ level: 30, msg: `loaded ${value}` }),
    `go ${encoded[1]}`,
    `secret data ${encoded[2]}`,
    `url-safe ${encoded[3]}`,
    `query ?v=${encoded[4]}`,
  ].join("\n");
  const lines = redactedQaTail(text, {}, { lines: 10, lineChars: 400 });
  assert.equal(lines.length, 6);
  for (const variant of [value, ...encoded]) {
    assert.ok(!lines.join("\n").includes(variant), `variant survived: ${lines.join("\n")}`);
  }
  assert.ok(
    lines.every((line) => line.includes("[env:qa-secret]")),
    lines.join("\n"),
  );
  const error = redactQaError(new Error(`failed: ${encoded[2]}`));
  assert.equal(error.message, "failed: [REDACTED]");
});

test("QA log tails drop the body of an unregistered key that starts above the tail", async () => {
  const { redactedQaTail } = await import("../helpers/qa-secrets.mjs");
  const lines = redactedQaTail(
    [
      "-----BEGIN OPENSSH PRIVATE KEY-----",
      "b3BlbnNzaC1rZXktdjEsyntheticAAAA",
      "syntheticBodyLineTwoBBBBBBBBBBBB",
      "-----END OPENSSH PRIVATE KEY-----",
      "after",
    ].join("\n"),
    {},
    { lines: 3, lineChars: 200 },
  );
  assert.deepEqual(lines, [
    "[redacted credential-bearing line]",
    "[redacted credential-bearing line]",
    "after",
  ]);
});
