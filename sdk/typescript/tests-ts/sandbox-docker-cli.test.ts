import { describe, expect, test } from "bun:test";
import { DockerCliEngine } from "../src/transport/sandbox/docker-cli.js";
import { SandboxOutputLimitError } from "../src/transport/sandbox/types.js";

describe("Docker CLI process boundary", () => {
  test("passes argv literally, closes stdin, and does not forward ambient secrets", async () => {
    process.env["CKODEX_SYNTHETIC_SECRET"] = "must-not-cross";
    const engine = new DockerCliEngine({
      executable: process.execPath,
      host: "tcp://docker.example:2375",
    });
    const result = await engine.run({
      args: [
        "-e",
        [
          "process.stdin.once('end',()=>process.stdout.write(JSON.stringify({",
          "arg:process.argv[1],",
          "dockerHost:process.env.DOCKER_HOST??null,",
          "secret:process.env.CKODEX_SYNTHETIC_SECRET??null",
          "})));process.stdin.resume()",
        ].join(""),
        "argument with spaces;$(not-a-shell)",
      ],
      signal: new AbortController().signal,
      maxOutputBytes: 4_096,
    });
    expect(JSON.parse(Buffer.from(result.stdout).toString("utf8"))).toEqual({
      arg: "argument with spaces;$(not-a-shell)",
      dockerHost: "tcp://docker.example:2375",
      secret: null,
    });
  });

  test("kills a process that exceeds the combined capture limit", async () => {
    const engine = new DockerCliEngine({ executable: process.execPath });
    await expect(
      engine.run({
        args: ["-e", "process.stdout.write('x'.repeat(4096))"],
        signal: new AbortController().signal,
        maxOutputBytes: 32,
      }),
    ).rejects.toBeInstanceOf(SandboxOutputLimitError);
  });

  test("kills the invoked process when the signal aborts", async () => {
    const engine = new DockerCliEngine({ executable: process.execPath });
    const controller = new AbortController();
    const pending = engine.run({
      args: ["-e", "setInterval(()=>{},1000)"],
      signal: controller.signal,
      maxOutputBytes: 32,
    });
    setTimeout(() => controller.abort(), 5);
    expect((await pending).exitCode).toBe(137);
  });
});
