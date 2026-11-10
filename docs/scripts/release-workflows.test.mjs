// SPDX-FileCopyrightText: 2026 INDUSTRIA DE DISEÑO TEXTIL S.A. (INDITEX S.A.)
// SPDX-License-Identifier: Apache-2.0

import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(import.meta.resolve('@antora/playbook-builder'));
const { load } = require('js-yaml');
const workflow = (name) => load(readFileSync(join(root, '../.github/workflows', name), 'utf8'));
const release = workflow('docouture-release.yml');
const preview = workflow('docouture-release-preview.yml');
const steps = release.jobs.release.steps;
const step = (name) => steps.find((entry) => entry.name === name);
const sha = 'a'.repeat(40);

function run(name, env = {}, { descriptor = '0.3.3', previewJob } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'cerbia-release-test-'));
  try {
    mkdirSync(join(dir, 'bin'));
    mkdirSync(join(dir, 'docs'));
    writeFileSync(join(dir, 'docs/.release-version'), descriptor);
    writeFileSync(join(dir, 'docs/antora-playbook.yml'), "tags: ['docs/v*']\n");
    writeFileSync(join(dir, 'output'), '');
    writeFileSync(join(dir, 'calls'), '');
    writeFileSync(join(dir, 'bin/git'), `#!/bin/bash
printf '%s\\n' "$*" >> "$CALLS"
case "$1" in
  ls-remote) exit "\${REMOTE_STATUS:-2}" ;;
  rev-parse)
    case "$2" in
      *tree*) if [[ "$2" == FETCH_HEAD* ]]; then echo "\${EXISTING_TREE:-same}"; else echo same; fi ;;
      *) echo '${sha}' ;;
    esac ;;
  status) printf '%s' "\${DIRTY:-}" ;;
  checkout) printf '%s' "\${MAIN_VERSION:-0.6.0}" > .release-version ;;
  diff) echo "\${STAGED_FILES:-docs/.release-version}" ;;
esac
`, { mode: 0o755 });
    writeFileSync(join(dir, 'bin/npx'), '#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\nif [ "$1" = antora ]; then exit "${BUILD_STATUS:-0}"; fi\n', { mode: 0o755 });
    writeFileSync(join(dir, 'bin/gh'), '#!/bin/bash\nprintf "%s\\n" "$*" >> "$CALLS"\n', { mode: 0o755 });
    const selected = previewJob
      ? preview.jobs[previewJob].steps.find((entry) => entry.name === name)
      : step(name);
    const result = spawnSync('/bin/bash', ['-e', '-o', 'pipefail', '-c', selected.run], {
      cwd: join(dir, 'docs'), encoding: 'utf8',
      env: { ...process.env, PATH: `${join(dir, 'bin')}:${process.env.PATH}`, GIT_MASTER: '1',
        GITHUB_OUTPUT: join(dir, 'output'), CALLS: join(dir, 'calls'), ...env },
    });
    return { ...result, output: readFileSync(join(dir, 'output'), 'utf8'),
      calls: readFileSync(join(dir, 'calls'), 'utf8'),
      descriptor: readFileSync(join(dir, 'docs/.release-version'), 'utf8') };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test('product v0.6.0 uses immutable event SHA and ignores stale descriptor/advanced main', () => {
  const source = run('Resolve source', { EVENT: 'release', RELEASE_TAG: 'v0.6.0', RELEASE_SHA: sha });
  assert.equal(source.status, 0, source.stderr);
  assert.equal(source.output, `ref=${sha}\nversion=0.6.0\n`);
  assert.equal(step('Checkout').with.ref, '${{ steps.source.outputs.ref }}');
  assert.ok(steps.indexOf(step('Resolve source')) < steps.indexOf(step('Checkout')));
  const version = run('Resolve version', { EVENT: 'release', PRODUCT_VERSION: '0.6.0' });
  assert.equal(version.output, 'version=0.6.0\n');
  assert.equal(run('Validate version', { MODE: 'versioned', EVENT: 'release', VERSION: '0.6.0' }).status, 0);
});

test('manual and docs-only PR keep their chosen version', () => {
  assert.equal(run('Resolve source', { EVENT: 'pull_request' }).output, 'ref=main\nversion=\n');
  assert.equal(run('Resolve version', { EVENT: 'workflow_dispatch', DISPATCH_VERSION: '0.5.2' }).output,
    'version=0.5.2\n');
  assert.equal(run('Resolve version', { EVENT: 'pull_request' }, { descriptor: '0.7.0' }).output,
    'version=0.7.0\n');
  assert.match(release.jobs.release.if, /skip-release/);
  assert.match(release.jobs.release.if, /release-type/);
});

test('product tags require v and immutable SHA; versions use strict SemVer', () => {
  for (const tag of ['0.6.0', 'docs/v0.6.0', '']) {
    assert.notEqual(run('Resolve source', { EVENT: 'release', RELEASE_TAG: tag, RELEASE_SHA: sha }).status, 0);
  }
  assert.notEqual(run('Resolve source', { EVENT: 'release', RELEASE_TAG: 'v0.6.0', RELEASE_SHA: 'main' }).status, 0);
  for (const version of ['', 'stable', 'v0.6.0', '0.6', '00.6.0', '0.6.0-01', '0.6.0/evil']) {
    assert.notEqual(run('Validate version', { MODE: 'versioned', EVENT: 'release', VERSION: version }).status, 0, version);
  }
  for (const version of ['0.6.0', '0.6.0-rc.1', '0.6.0+build.2']) {
    assert.equal(run('Validate version', { MODE: 'versioned', VERSION: version }).status, 0, version);
  }
  assert.ok(steps.indexOf(step('Validate version')) < steps.indexOf(step('Cut release')));
});

test('existing tag conflicts fail, matching trees rerun safely, remote errors fail closed', () => {
  const env = { TAG: 'docs/v0.6.0', SHA: sha, EVENT: 'release', REMOTE_STATUS: '0' };
  assert.notEqual(run('Check for existing release', { ...env, EXISTING_TREE: 'different' }).status, 0);
  assert.equal(run('Check for existing release', env).output, 'existed=true\n');
  assert.equal(run('Check for existing release', { ...env, EVENT: 'workflow_dispatch', EXISTING_TREE: 'different' }).status, 0);
  assert.equal(run('Check for existing release', { ...env, REMOTE_STATUS: '2' }).output, 'existed=false\n');
  assert.notEqual(run('Check for existing release', { ...env, REMOTE_STATUS: '128' }).status, 0);
  assert.equal(run('Push release tag', { ...env, MODE: 'versioned', EXISTED: 'true' }).calls, '');
  const fresh = run('Push release tag', { ...env, MODE: 'versioned', EXISTED: 'false' });
  assert.match(fresh.calls, /push origin refs\/tags\/docs\/v0.6.0\n/);
  assert.ok(!fresh.calls.includes('--force'));
  assert.match(run('Push release tag', { ...env, EVENT: 'workflow_dispatch' }).calls, /--force/);
});

test('exact numbered descriptor builds before tag and only its descriptor is staged', () => {
  const cut = run('Cut release', { MODE: 'versioned', VERSION: '0.6.0' });
  assert.equal(cut.status, 0, cut.stderr);
  assert.match(cut.calls, /docouture version 0.6.0\nadd src\/antora.yml\nantora .*local.yml\ncommit/);
  assert.match(cut.output, /tag=docs\/v0.6.0/);
  assert.ok(!cut.calls.includes('push'));
  const failed = run('Cut release', { MODE: 'versioned', VERSION: '0.6.0', BUILD_STATUS: '1' });
  assert.notEqual(failed.status, 0);
  assert.ok(!failed.calls.includes('commit'));
  assert.ok(!failed.output.includes('tag='));
});

test('bookkeeping refreshes main, preserves another target, and stages no unrelated files', () => {
  for (const version of ['0.7.0', '0.3.3']) {
    const kept = run('Bump release descriptor', { VERSION: '0.6.0', MAIN_VERSION: version });
    assert.equal(kept.status, 0, kept.stderr);
    assert.equal(kept.descriptor, version);
    assert.equal(kept.calls, 'status --porcelain\nfetch --no-tags origin main\ncheckout -B main FETCH_HEAD\n');
  }
  const bumped = run('Bump release descriptor', { VERSION: '0.6.0', MAIN_VERSION: '0.6.0' });
  assert.equal(bumped.status, 0, bumped.stderr);
  assert.equal(bumped.descriptor, '0.6.1\n');
  assert.match(bumped.calls, /checkout -B main FETCH_HEAD[\s\S]*add .release-version[\s\S]*push origin HEAD:refs\/heads\/main/);
  for (const env of [{ DIRTY: ' M unrelated' }, { STAGED_FILES: 'unrelated' }]) {
    const rejected = run('Bump release descriptor', { VERSION: '0.6.0', ...env });
    assert.notEqual(rejected.status, 0);
    assert.ok(!rejected.calls.includes('push'));
  }
});

test('bookkeeping condition retries automatic existing tags but skips manual republishes', () => {
  const condition = step('Bump release descriptor').if;
  assert.equal(condition,
    "steps.detect.outputs.mode == 'versioned' && (steps.check.outputs.existed != 'true' || github.event_name != 'workflow_dispatch')");
  for (const [mode, existed, event, expected] of [
    ['versioned', 'true', 'release', 0],
    ['versioned', 'true', 'pull_request', 0],
    ['versioned', 'true', 'workflow_dispatch', 1],
    ['versioned', 'false', 'workflow_dispatch', 0],
    ['standalone', 'false', 'release', 1],
  ]) {
    const expression = condition
      .replaceAll('steps.detect.outputs.mode', `'${mode}'`)
      .replaceAll('steps.check.outputs.existed', `'${existed}'`)
      .replaceAll('github.event_name', `'${event}'`);
    const result = spawnSync('/bin/bash', ['-c', `[[ ${expression} ]]`]);
    assert.equal(result.status, expected, `${mode}/${existed}/${event}`);
  }
});

test('coupled preview waits for authoritative product release, docs-only preview retains target', () => {
  const env = { MODE: 'versioned', VERSION: '0.3.3', TAG: 'docs/v0.3.3', COUPLED: 'true' };
  const coupled = run('Comment on PR', env, { previewJob: 'release-preview' });
  assert.equal(coupled.status, 0, coupled.stderr);
  assert.match(coupled.calls, /defers docs tagging until the product GitHub Release/);
  assert.match(coupled.calls, /release-type\/minor/);
  assert.ok(!coupled.calls.includes('will release the docs site as'));
  const direct = run('Comment on PR', { ...env, COUPLED: 'false', EXISTED: 'true' }, { previewJob: 'release-preview' });
  assert.match(direct.calls, /will release the docs site as.*docs\/v0.3.3/);
  assert.match(direct.calls, /fails on different content/);
});

test('publication uses current main tooling and existing security boundaries remain', () => {
  assert.equal(workflow('docouture-publish.yml').jobs.publish.steps[0].with.ref, 'main');
  assert.equal(readFileSync(join(root, '.release-version'), 'utf8'), '0.6.0\n');
  assert.equal(release.jobs.release.permissions.contents, 'read');
  assert.equal(step('Git app token').with.repositories, '${{ github.event.repository.name }}');
  assert.equal(step('Setup Node').with['package-manager-cache'], false);
  assert.equal(step('Checkout').with['persist-credentials'], false);
  assert.deepEqual(Object.keys(release.jobs.publish.secrets), ['APP_PRIVATE_KEY']);
  for (const entry of steps.filter((entry) => entry.uses)) assert.match(entry.uses, /@[a-f0-9]{40}$/);
});
