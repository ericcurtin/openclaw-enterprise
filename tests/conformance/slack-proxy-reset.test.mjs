import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import net from "node:net";
import test from "node:test";
import { availablePort } from "../helpers/available-port.mjs";

test("a refused CONNECT reset leaves the Slack proxy running", async (t) => {
  const proxyPort = await availablePort();
  const child = spawn(process.execPath, ["apps/controller/src/slack-proxy.mjs"], {
    cwd: new URL("../../", import.meta.url),
    env: { ...process.env, OCC_SLACK_PROXY_PORT: String(proxyPort) },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  t.after(() => child.kill());
  await waitForProxy(proxyPort);

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const socket = net.connect({ host: "127.0.0.1", port: proxyPort });
    await new Promise((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", reject);
    });
    socket.write("CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n");
    socket.resetAndDestroy();
  }

  let response;
  try {
    response = await connectThroughProxy(proxyPort, "example.com:443");
  } catch (error) {
    assert.fail(`proxy exited ${child.exitCode}: ${stderr}\n${error}`);
  }
  assert.match(response, /^HTTP\/1\.1 403 Forbidden/);
  assert.equal(child.exitCode, null);
  assert.doesNotMatch(stderr, /unhandled/i);
});

async function waitForProxy(port) {
  const started = Date.now();
  while (Date.now() - started < 5_000) {
    try {
      const socket = net.connect({ host: "127.0.0.1", port });
      await new Promise((resolve, reject) => {
        socket.once("connect", resolve);
        socket.once("error", reject);
      });
      socket.end();
      return;
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
  }
  throw new Error("Slack proxy did not start.");
}

async function connectThroughProxy(port, target) {
  const socket = net.connect({ host: "127.0.0.1", port });
  let response = "";
  try {
    await new Promise((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error("proxy response timeout")), 10_000);
      const finish = () => {
        clearTimeout(timeout);
        resolve();
      };
      socket.once("error", reject);
      socket.once("connect", () => {
        socket.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`);
      });
      socket.on("data", (chunk) => {
        response += chunk;
        if (response.includes("\r\n\r\n")) {
          finish();
        }
      });
      socket.once("end", finish);
    });
    return response;
  } finally {
    socket.destroy();
  }
}
