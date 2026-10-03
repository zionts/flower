// Narrow source contract, deliberately not a substitute for Nix evaluation/build.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const flake = readFileSync(new URL("../flake.nix", import.meta.url), "utf8");
const cargo = readFileSync(new URL("../Cargo.toml", import.meta.url), "utf8");
const section = (start, end) => flake.slice(flake.indexOf(start), flake.indexOf(end));

test("SQL is an explicit server artifact, never a Cargo or flake default", () => {
  const features = cargo.match(/\[features\]([\s\S]*?)(?=\n\[)/)?.[1];
  assert.ok(features, "Cargo feature declarations must be present");
  assert.match(features, /^default\s*=\s*\[\s*\]\s*$/m);
  assert.match(features, /^sql\s*=\s*\["dep:libsqlite3-sys"\]/m);
  const factory = section("      mkFlower =", "      # @flower-js/sdk");
  assert.match(factory, /\{ enableSql \? false \}:/);
  assert.match(factory, /cargoBuildFlags\s*=\s*\[\s*"--bin"\s*"flower"\s*\]\s*\+\+\s*lib\.optionals enableSql\s*\[\s*"--features"\s*"sql"\s*\]/);
  assert.doesNotMatch(factory, /cargo(?:BuildFeatures|Features|ExtraArgs)\s*=/);
  const packages = section("      packages = forAllSystems", "      apps = forAllSystems");
  assert.match(packages, /flower = mkFlower pkgs \{\s*\};/);
  assert.match(packages, /default = flower;/);
  assert.match(packages, /flower-sql = mkFlower pkgs \{ enableSql = true; \};/);
  assert.equal((packages.match(/enableSql = true/g) ?? []).length, 1);
});

test("SQL-enabled app, overlay and compile check stay separately selectable", () => {
  const apps = section("      apps = forAllSystems", "      overlays.default =");
  assert.match(apps, /program = "\$\{packages\.flower\}\/bin\/flower";/);
  assert.match(apps, /default = server;\s*flower = server;/);
  assert.match(apps, /flower-sql = \{\s*type = "app";\s*program = "\$\{packages\.flower-sql\}\/bin\/flower";/);
  const overlay = section("      overlays.default =", "      nixosModules =");
  assert.match(overlay, /flower = self\.packages\.\$\{final\.stdenv\.hostPlatform\.system\}\.flower;/);
  assert.match(overlay, /flower-sql = self\.packages\.\$\{final\.stdenv\.hostPlatform\.system\}\.flower-sql;/);
  assert.match(section("      checks = forAllSystems", "      formatter ="), /inherit \(packages\) flower flower-sql sdk;/);
});

test("server source includes the redb seam even before it exists", () => {
  const source = section("      serverSrc =", "      sdkSrc =");
  assert.match(source, /\(lib\.fileset\.maybeMissing \.\/vendor\/redb\)/);
  assert.match(source, /\.\/Cargo\.toml/);
  assert.match(source, /\.\/Cargo\.lock/);
  assert.match(source, /\.\/src/);
  assert.match(source, /\.\/vendor\/quickjs-ng\/quickjs\.wasm/);
});
