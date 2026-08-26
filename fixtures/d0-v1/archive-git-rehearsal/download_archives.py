#!/usr/bin/env python3
import concurrent.futures, datetime, hashlib, json, os, pathlib, re, ssl, subprocess, sys, threading, time, urllib.error, urllib.request

CATALOG_REPO = pathlib.Path('/home/dev0/repos/pkgre-rust')
CATALOG_COMMIT = 'f9b5ffaf14c2b9278c9d4828dc4e8b9ef8f6518b'
MANIFEST_PATH = 'registry/downloads.json'
CONCURRENCY = 8
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
ATTEMPTS = 3
CONNECT_AND_READ_TIMEOUT_SECONDS = 120
CHUNK = 1024 * 1024
RUN = pathlib.Path(sys.argv[1]).resolve()
OBJECTS = RUN / 'objects'
OBJECTS.mkdir(mode=0o700, exist_ok=True)
manifest_bytes = subprocess.run(['git','-C',str(CATALOG_REPO),'show',f'{CATALOG_COMMIT}:{MANIFEST_PATH}'], check=True, stdout=subprocess.PIPE).stdout
(RUN / 'downloads.json').write_bytes(manifest_bytes)
manifest = json.loads(manifest_bytes)
assert manifest.get('schema') == 1
routes = manifest.get('routes')
assert isinstance(routes, list) and len(routes) == 747
hex64 = re.compile(r'^[0-9a-f]{64}$')
name_re = re.compile(r'^[A-Za-z0-9_-]+$')
seen_ids = set()
by_hash = {}
for i, r in enumerate(routes):
    assert set(r) == {'registry','name','version','sha256','source'}
    assert r['registry'] == 'main'
    assert isinstance(r['name'], str) and name_re.fullmatch(r['name'])
    assert isinstance(r['version'], str) and r['version'] and all(c.isalnum() or c in '.+-' for c in r['version'])
    assert isinstance(r['sha256'], str) and hex64.fullmatch(r['sha256'])
    assert r['source'] in {'crates-io','git-tag'}
    identity = (r['registry'],r['name'],r['version'])
    assert identity not in seen_ids
    seen_ids.add(identity)
    r = dict(r, route_index=i)
    by_hash.setdefault(r['sha256'], []).append(r)

def no_redirect_opener():
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    # Direct HTTPS only: ignore ambient proxy configuration; no auth handlers or credentials.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=ssl.create_default_context()), NoRedirect())

def hash_file(path):
    h = hashlib.sha256(); n = 0
    with open(path, 'rb') as f:
        while chunk := f.read(CHUNK): h.update(chunk); n += len(chunk)
    return h.hexdigest(), n

def fetch_one(item):
    expected, grouped = item
    route = grouped[0]
    if any(x['source'] != route['source'] or x['name'] != route['name'] or x['version'] != route['version'] for x in grouped[1:]):
        return {'sha256': expected, 'ok': False, 'routes': grouped, 'error': 'same hash declared by incompatible source identities'}
    final = OBJECTS / f'{expected}.crate'
    started = time.monotonic()
    meta = {}
    try:
        if route['source'] == 'git-tag':
            git_path = f'registry/objects/crates/{expected}.crate'
            body = subprocess.run(['git','-C',str(CATALOG_REPO),'show',f'{CATALOG_COMMIT}:{git_path}'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
            if len(body) > MAX_ARCHIVE_BYTES: raise ValueError(f'body exceeds {MAX_ARCHIVE_BYTES}')
            final.write_bytes(body)
            url = f'git:{CATALOG_COMMIT}:{git_path}'
            meta = {'transport':'locked-git-blob'}
        else:
            url = f"https://static.crates.io/crates/{route['name']}/{route['version']}/download"
            last = None
            for attempt in range(1, ATTEMPTS + 1):
                part = OBJECTS / f'.{expected}.{threading.get_ident()}.part'
                try:
                    req = urllib.request.Request(url, headers={'Accept':'application/octet-stream','Accept-Encoding':'identity','User-Agent':'pkgre-d0-archive-rehearsal/1'}, method='GET')
                    with no_redirect_opener().open(req, timeout=CONNECT_AND_READ_TIMEOUT_SECONDS) as resp, open(part, 'wb') as out:
                        status = getattr(resp, 'status', None)
                        if status != 200 or resp.geturl() != url: raise ValueError(f'unexpected response status={status} final_url={resp.geturl()!r}')
                        h = hashlib.sha256(); n = 0
                        while chunk := resp.read(CHUNK):
                            n += len(chunk)
                            if n > MAX_ARCHIVE_BYTES: raise ValueError(f'body exceeds {MAX_ARCHIVE_BYTES}')
                            h.update(chunk); out.write(chunk)
                        out.flush(); os.fsync(out.fileno())
                        got = h.hexdigest()
                        if got != expected: raise ValueError(f'sha256 mismatch expected={expected} actual={got}')
                        os.replace(part, final)
                        meta = {'transport':'direct-https-no-proxy-no-redirect','status':status,'content_length':resp.headers.get('Content-Length'),'etag':resp.headers.get('ETag'),'last_modified':resp.headers.get('Last-Modified'),'attempt':attempt}
                        break
                except Exception as e:
                    last = e
                    try: part.unlink()
                    except FileNotFoundError: pass
                    if attempt == ATTEMPTS: raise
                    time.sleep(2 ** (attempt - 1))
        got, size = hash_file(final)
        if got != expected: raise ValueError(f'post-write sha256 mismatch expected={expected} actual={got}')
        return {'sha256': expected, 'ok': True, 'bytes': size, 'source': route['source'], 'url': url, 'routes': grouped, 'seconds': time.monotonic()-started, **meta}
    except Exception as e:
        try: final.unlink()
        except FileNotFoundError: pass
        return {'sha256': expected, 'ok': False, 'source': route['source'], 'url': locals().get('url'), 'routes': grouped, 'seconds': time.monotonic()-started, 'error': f'{type(e).__name__}: {e}'}

started_wall = datetime.datetime.now(datetime.timezone.utc)
started = time.monotonic()
with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY, thread_name_prefix='crate') as pool:
    results = list(pool.map(fetch_one, sorted(by_hash.items())))
elapsed = time.monotonic() - started
ended_wall = datetime.datetime.now(datetime.timezone.utc)
results.sort(key=lambda x: x['sha256'])
failed = [x for x in results if not x['ok']]
ok = [x for x in results if x['ok']]
summary = {
  'catalog_repo': str(CATALOG_REPO), 'catalog_commit': CATALOG_COMMIT, 'manifest_path': MANIFEST_PATH,
  'manifest_sha256': hashlib.sha256(manifest_bytes).hexdigest(), 'manifest_bytes': len(manifest_bytes),
  'route_count': len(routes), 'unique_hash_count': len(by_hash),
  'source_route_counts': {s:sum(r['source']==s for r in routes) for s in ['crates-io','git-tag']},
  'concurrency': CONCURRENCY, 'attempts': ATTEMPTS, 'timeout_seconds': CONNECT_AND_READ_TIMEOUT_SECONDS,
  'max_archive_bytes': MAX_ARCHIVE_BYTES, 'started_utc': started_wall.isoformat(), 'ended_utc': ended_wall.isoformat(), 'download_seconds': elapsed,
  'verified_unique_count': len(ok), 'failed_unique_count': len(failed),
  'verified_route_count': sum(len(x['routes']) for x in ok), 'failed_route_count': sum(len(x['routes']) for x in failed),
  'raw_unique_bytes': sum(x['bytes'] for x in ok), 'logical_route_bytes': sum(x['bytes'] * len(x['routes']) for x in ok),
  'largest_archive_bytes': max((x['bytes'] for x in ok), default=0),
  'largest_archive_sha256': max(ok, key=lambda x:x['bytes'])['sha256'] if ok else None,
}
(RUN / 'download-results.json').write_text(json.dumps({'summary':summary,'objects':results}, indent=2, sort_keys=True)+'\n')
(RUN / 'download-summary.json').write_text(json.dumps(summary, indent=2, sort_keys=True)+'\n')
(RUN / 'failures.json').write_text(json.dumps(failed, indent=2, sort_keys=True)+'\n')
print(json.dumps(summary, indent=2, sort_keys=True))
if failed: sys.exit(1)
