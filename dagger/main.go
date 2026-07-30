package main

import (
	"context"
	"dagger/codex-security-ci/internal/dagger"
)

type CodexSecurityCi struct{}

const (
	nodeImage           = "node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3"
	bunImage            = "oven/bun:1.3.14@sha256:e10577f0db68676a7024391c6e5cb4b879ebd17188ab750cf10024a6d700e5c4"
	dockerCliImage      = "docker:27.4.0-cli@sha256:561338cb111f09a755c9c28e00b66a2466a3dacd88bca6f2f0aeaf909e95730a"
	dockerDindImage     = "docker:27.4.0-dind@sha256:b0c1179ea32ad77bdb7b852b037e54b11022304c2f2662af1954ef53869314b2"
	sandboxFixtureImage = "node@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3"
	syftImage           = "anchore/syft:v1.49.0"
	cosignImage         = "gcr.io/projectsigstore/cosign:v3.1.2"
)

var sourceExcludes = []string{
	".git",
	".git/**",
	"**/node_modules",
	"**/node_modules/**",
	"**/dist",
	"**/dist/**",
	"results",
	"results/**",
	"state",
	"state/**",
}

func (m *CodexSecurityCi) sdk(source *dagger.Directory) *dagger.Container {
	bun := dag.Container().From(bunImage).File("/usr/local/bin/bun")
	return dag.Container().
		From(nodeImage).
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{
			"apt-get",
			"install",
			"--yes",
			"--no-install-recommends",
			"python3",
			"ca-certificates",
			"git",
		}).
		WithExec([]string{"rm", "-rf", "/var/lib/apt/lists"}).
		WithFile("/usr/local/bin/bun", bun).
		WithDirectory("/src", source, dagger.ContainerWithDirectoryOpts{
			Exclude: sourceExcludes,
		}).
		WithWorkdir("/src/sdk/typescript").
		WithMountedCache("/pnpm/store", dag.CacheVolume("codex-security-pnpm-v1")).
		WithEnvVariable("PNPM_HOME", "/pnpm").
		WithEnvVariable("COREPACK_HOME", "/corepack").
		WithEnvVariable("CI", "true").
		WithExec([]string{"corepack", "enable"}).
		WithExec([]string{
			"pnpm",
			"install",
			"--frozen-lockfile",
			"--store-dir",
			"/pnpm/store",
		})
}

func run(ctx context.Context, container *dagger.Container, command ...string) (string, error) {
	return container.WithExec(command).Stdout(ctx)
}

func withPackageCheck(container *dagger.Container) *dagger.Container {
	return container.
		WithExec([]string{"mkdir", "-p", "/tmp/package"}).
		WithExec([]string{"pnpm", "pack", "--pack-destination", "/tmp/package"}).
		WithExec([]string{
			"sh", "-ec", "pnpm run check:package /tmp/package/*.tgz",
		}).
		WithExec([]string{
			"sh",
			"-ec",
			"pnpm run check:package /tmp/package/*.tgz",
		})
}

func withSupplyChain(container *dagger.Container) *dagger.Container {
	syft := dag.Container().From(syftImage).File("/syft")
	cosign := dag.Container().From(cosignImage).File("/ko-app/cosign")
	root := "capabilities/provider-projection"
	return container.
		WithFile("/usr/local/bin/syft", syft).
		WithFile("/usr/local/bin/cosign", cosign).
		WithEnvVariable("CKODEX_EVIDENCE_DIR", "/tmp/evidence").
		WithExec([]string{"pnpm", "run", "quality"}).
		WithExec([]string{"pnpm", "run", "build"}).
		WithExec([]string{"mkdir", "-p", "/tmp/package"}).
		WithExec([]string{"pnpm", "pack", "--pack-destination", "/tmp/package"}).
		WithExec([]string{
			"cosign", "verify-blob", "--insecure-ignore-tlog",
			"--bundle", root + "/signatures/lock.sigstore.json",
			"--key", root + "/cosign.pub", root + "/lock.json",
		}).
		WithExec([]string{
			"cosign", "verify-blob", "--insecure-ignore-tlog",
			"--bundle", root + "/signatures/bundle.sigstore.json",
			"--key", root + "/cosign.pub", root + "/bundle.json",
		}).
		WithExec([]string{
			"sh", "-ec",
			"node scripts/create-supply-chain-evidence.mjs /tmp/package/*.tgz /tmp/evidence",
		})
}

// Architecture verifies dependency direction across the four spaces.
func (m *CodexSecurityCi) Architecture(ctx context.Context, source *dagger.Directory) (string, error) {
	return run(ctx, m.sdk(source), "pnpm", "run", "architecture")
}

// Types verifies generated models and TypeScript types.
func (m *CodexSecurityCi) Types(ctx context.Context, source *dagger.Directory) (string, error) {
	return run(ctx, m.sdk(source), "pnpm", "run", "types")
}

// Test runs the TypeScript SDK test suite with its Python boundary available.
func (m *CodexSecurityCi) Test(ctx context.Context, source *dagger.Directory) (string, error) {
	return run(ctx, m.sdk(source), "pnpm", "run", "test")
}

// Model verifies local-process, loopback, private TLS, gRPC, continuation, admission, and provider projection paths.
func (m *CodexSecurityCi) Model(ctx context.Context, source *dagger.Directory) (string, error) {
	return run(ctx, m.sdk(source),
		"bun", "test", "--timeout", "30000",
		"tests-ts/model-cancellation.test.ts",
		"tests-ts/model-config.test.ts",
		"tests-ts/model-continuation.test.ts",
		"tests-ts/model-endpoint-security.test.ts",
		"tests-ts/model-live-http.test.ts",
		"tests-ts/model-local-process.test.ts",
		"tests-ts/model-docker-process-runner.test.ts",
		"tests-ts/model-openai-compatible.test.ts",
		"tests-ts/model-pinned-tls.test.ts",
		"tests-ts/model-private-grpc.test.ts",
		"tests-ts/model-responses-sse.test.ts",
		"tests-ts/architecture-integration-model-execution.test.ts",
		"tests-ts/architecture-integration-provider-selection.test.ts",
		"tests-ts/public-model-composition.test.ts",
		"tests-ts/validation-model-capabilities.test.ts",
		"tests-ts/cli.test.ts",
		"tests-ts/config.test.ts",
	)
}

// Quality enforces source limits and the minimum line-coverage threshold.
func (m *CodexSecurityCi) Quality(ctx context.Context, source *dagger.Directory) (string, error) {
	return run(ctx, m.sdk(source), "pnpm", "run", "quality")
}

// Governance verifies the production governance binding and durable evidence boundary.
func (m *CodexSecurityCi) Governance(ctx context.Context, source *dagger.Directory) (string, error) {
	container := m.sdk(source).
		WithExec([]string{
			"bun", "test", "--timeout", "30000",
			"tests-ts/production-governance.test.ts",
			"tests-ts/governance-workbench-integration.test.ts",
		}).
		WithExec([]string{
			"node", "scripts/check-quality.mjs",
			"src/kernel/governance-contracts.ts",
			"src/proof/production-governance.ts",
			"src/transport/workbench-governance-evidence.ts",
			"_bundled_plugin/scripts/workbench_governance.py",
			"_bundled_plugin/scripts/workbench_governance_action_validation.py",
			"_bundled_plugin/scripts/workbench_governance_validation.py",
		})
	return run(ctx, container, "node", "-e", "process.stdout.write('governance verification passed\\n')")
}

// SupplyChain exports coverage, CycloneDX SBOM, and deterministic local provenance after offline signature verification.
func (m *CodexSecurityCi) SupplyChain(ctx context.Context, source *dagger.Directory) (*dagger.Directory, error) {
	container := withSupplyChain(m.sdk(source))
	if _, err := container.WithExec([]string{"pnpm", "run", "test:supply-chain"}).Sync(ctx); err != nil {
		return nil, err
	}
	return container.Directory("/tmp/evidence"), nil
}

// SandboxLive validates the granted host daemon, then runs sandbox and model-process acceptance in Docker-in-Docker.
func (m *CodexSecurityCi) SandboxLive(ctx context.Context, source *dagger.Directory, dockerSocket *dagger.Socket) (string, error) {
	docker := dag.Container().From(dockerCliImage).File("/usr/local/bin/docker")
	sharedRoot := dag.CacheVolume("codex-security-sandbox-live-v1")
	daemon := dag.Container().
		From(dockerDindImage).
		WithEnvVariable("DOCKER_TLS_CERTDIR", "").
		WithMountedCache("/sandbox", sharedRoot, dagger.ContainerWithMountedCacheOpts{
			Sharing: dagger.CacheSharingModeShared,
		}).
		WithExposedPort(2375).
		AsService(dagger.ContainerAsServiceOpts{
			Args:                     []string{"--host=tcp://0.0.0.0:2375", "--tls=false"},
			UseEntrypoint:            true,
			InsecureRootCapabilities: true,
		})
	container := m.sdk(source).
		WithFile("/usr/local/bin/docker", docker).
		WithUnixSocket("/var/run/host-docker.sock", dockerSocket).
		WithExec([]string{
			"docker",
			"--host",
			"unix:///var/run/host-docker.sock",
			"version",
			"--format",
			"{{.Server.Version}}",
		}).
		WithoutUnixSocket("/var/run/host-docker.sock").
		WithMountedCache("/sandbox", sharedRoot, dagger.ContainerWithMountedCacheOpts{
			Sharing: dagger.CacheSharingModeShared,
		}).
		WithServiceBinding("docker", daemon).
		WithEnvVariable("DOCKER_HOST", "tcp://docker:2375").
		WithEnvVariable("CKODEX_TEST_DOCKER_HOST", "tcp://docker:2375").
		WithEnvVariable("TMPDIR", "/sandbox/tmp").
		WithExec([]string{"mkdir", "-p", "/sandbox/tmp"}).
		WithExec([]string{"docker", "pull", sandboxFixtureImage}).
		WithExec([]string{
			"docker",
			"run",
			"--rm",
			"--pull=never",
			"--mount",
			"type=bind,src=/sandbox/tmp,dst=/sandbox-root",
			sandboxFixtureImage,
			"node",
			"-e",
			"require('node:fs').writeFileSync('/sandbox-root/dind-probe','ok')",
		}).
		WithExec([]string{"rm", "/sandbox/tmp/dind-probe"})
	return run(ctx, container, "pnpm", "run", "test:sandbox:live")
}

// Format checks repository formatting for the TypeScript package.
func (m *CodexSecurityCi) Format(ctx context.Context, source *dagger.Directory) (string, error) {
	return run(ctx, m.sdk(source), "pnpm", "run", "format")
}

// Build compiles the TypeScript package.
func (m *CodexSecurityCi) Build(ctx context.Context, source *dagger.Directory) (string, error) {
	return run(ctx, m.sdk(source), "pnpm", "run", "build")
}

// Package verifies that the built package contains the expected artifacts.
func (m *CodexSecurityCi) Package(ctx context.Context, source *dagger.Directory) (string, error) {
	container := m.sdk(source).WithExec([]string{"pnpm", "run", "build"})
	return run(ctx, withPackageCheck(container), "node", "-e", "process.stdout.write('package verification passed\\n')")
}

// All executes the complete portable verification sequence.
func (m *CodexSecurityCi) All(ctx context.Context, source *dagger.Directory) (string, error) {
	container := m.sdk(source)
	for _, command := range [][]string{
		{"pnpm", "run", "architecture"},
		{"pnpm", "run", "types"},
		{"pnpm", "run", "format"},
	} {
		container = container.WithExec(command)
	}
	container = withSupplyChain(container)
	return container.WithExec([]string{"node", "-e", "process.stdout.write('all verification gates passed\\n')"}).Stdout(ctx)
}
