import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { test } from 'node:test';

assert.ok(process.env.SITE_DIR, 'Set SITE_DIR to the generated site to inspect (read-only)');
const site = resolve(process.env.SITE_DIR);
const search = join(site, '_/search');
const indexes = readdirSync(search).filter((name) => /^ROOT-.+\.json$/.test(name));
const html = (path) => readFileSync(join(site, path), 'utf8');

test('native search URLs carry /cerbia exactly once and resolve to pages and anchors', () => {
  assert.ok(indexes.length > 0, 'No ROOT search indexes generated');
  let records = 0;
  let anchors = 0;
  for (const name of indexes) {
    const version = name.slice(5, -5);
    const index = JSON.parse(readFileSync(join(search, name), 'utf8'));
    assert.equal(index.componentVersion, version);
    assert.ok(index.records.length > 0, `Empty index: ${name}`);
    for (const record of index.records) {
      assert.ok(record.url.startsWith(`/cerbia/${version}/`), record.url);
      assert.ok(!record.url.startsWith('/cerbia/cerbia/'), record.url);
      const url = new URL(record.url, 'https://inditextech.github.io');
      assert.equal(url.pathname, record.url.split('#')[0], record.url);
      const page = html(`${decodeURIComponent(url.pathname.slice('/cerbia/'.length))}index.html`);
      if (url.hash) {
        assert.ok(page.includes(`id="${decodeURIComponent(url.hash.slice(1))}"`), record.url);
        anchors++;
      }
      records++;
    }
  }
  assert.ok(anchors > 0, 'No section search records checked');
  console.log(`SEARCH_OK indexes=${indexes.length} records=${records} anchors=${anchors} site=${site}`);
});

test('latest is an unchanged release copy sharing the numbered search index, never a prerelease alias', () => {
  assert.ok(!indexes.includes('ROOT-latest.json'));
  const released = indexes.filter((name) => name !== 'ROOT-prerelease.json');
  if (!released.length) assert.ok(!existsSync(join(site, 'latest')));
  if (!existsSync(join(site, 'latest'))) return;
  const latest = html('latest/index.html');
  const source = latest.match(/data-search-index="(ROOT-[^"]+\.json)"/)?.[1];
  assert.ok(released.includes(source), `Unexpected latest search index: ${source}`);
  const version = source.slice(5, -5);
  assert.equal(latest, html(`${version}/index.html`));
  assert.ok(latest.includes(`https://inditextech.github.io/cerbia/${version}/`));
  console.log(`LATEST_OK source=${version}`);
});
