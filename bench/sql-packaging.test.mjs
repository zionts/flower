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
  const sql = [...(features.match(/^sql\s*=\s*\[([^\]]*)\]/m)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((match) => match[1]);
  // The deny-only generic source/lifetime core needs bounded native readers
  // even when SQL serving is OFF. SQLite and mounted SQL crypto stay optional.
  const expectedSql = ["dep:libsqlite3-sys", "dep:aes-gcm", "dep:aes", "dep:ghash", "dep:polyval"];
  assert.deepEqual([...sql].sort(), expectedSql.sort(), "every SQL-only dependency/feature is explicit and unique");
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

test("generic lifetime gates keep both bounded readers with SQL serving OFF", () => {
  const dependencies = cargo.match(/\[dependencies\]([\s\S]*?)(?=\n\[)/)?.[1];
  assert.ok(dependencies, "native dependency declarations must be present");
  for (const [name, feature] of [["im", "flower-bounded-reads"], ["redb", "flower-resident-reads"]]) {
    const declaration = dependencies.match(new RegExp(`^${name}\\s*=\\s*\\{([^\\n]*)\\}\\s*$`, "m"))?.[1];
    assert.ok(declaration, `${name} is a generic native dependency`);
    assert.doesNotMatch(declaration, /optional\s*=\s*true/, `${name} must not disappear when SQL is OFF`);
    const features = [...(declaration.match(/features\s*=\s*\[([^\]]*)\]/)?.[1] ?? "").matchAll(/"([^"]+)"/g)].map((match) => match[1]);
    assert.deepEqual(features, [feature], `${name} must explicitly retain its exact bounded-reader seam`);
  }
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

test("server source includes both native capture vendor seams", () => {
  const source = section("      serverSrc =", "      sdkSrc =");
  assert.match(source, /\(lib\.fileset\.maybeMissing \.\/vendor\/redb\)/);
  assert.match(source, /\.\/vendor\/im/);
  assert.match(source, /\.\/Cargo\.toml/);
  assert.match(source, /\.\/Cargo\.lock/);
  assert.match(source, /\.\/src/);
  assert.match(source, /\.\/vendor\/quickjs-ng\/quickjs\.wasm/);
});
