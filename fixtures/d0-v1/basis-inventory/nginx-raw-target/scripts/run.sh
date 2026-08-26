#!/usr/bin/env bash
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
NGINX=${NGINX:-/nix/store/qzihfqlvbzx0zhjvmx6zimxdz9ghvwm0-nginx-1.30.4/bin/nginx}
PYTHON=${PYTHON:-/nix/store/x0pgrsmsbp4z4lm2az6dl3gqn6pjy61r-python3-3.14.7-env/bin/python}
OPENSSL=${OPENSSL:-/nix/store/d4vvjf2zix40pq13w778cz4hkyna90ii-openssl-3.6.3-bin/bin/openssl}
OBSERVE_PORT=${OBSERVE_PORT:-19781}
POLICY_PORT=${POLICY_PORT:-19782}
RUNTIME=$(mktemp -d /tmp/d0-nginx-proof.XXXXXX)
BACKEND_PID=
NGINX_PID=
cleanup() {
  set +e
  if [[ -n "$NGINX_PID" ]]; then kill "$NGINX_PID" 2>/dev/null; wait "$NGINX_PID" 2>/dev/null; fi
  if [[ -n "$BACKEND_PID" ]]; then kill "$BACKEND_PID" 2>/dev/null; wait "$BACKEND_PID" 2>/dev/null; fi
  for f in nginx-error.log nginx.conf proxy-common.conf proxy-observe.conf proxy-policy.conf; do
    [[ -f "$RUNTIME/$f" ]] && cp "$RUNTIME/$f" "$ROOT/results/$f"
  done
  rm -rf "$RUNTIME"
}
trap cleanup EXIT
for x in "$NGINX" "$PYTHON" "$OPENSSL"; do [[ -x "$x" ]] || { echo "missing executable: $x" >&2; exit 1; }; done
rm -rf "$ROOT/results"
mkdir -p "$ROOT/results/backend" "$ROOT/results/h1-observe" "$ROOT/results/h1-policy" "$ROOT/results/h2-observe" "$ROOT/results/h2-policy"
"$ROOT/scripts/generate_fixtures.py" > "$ROOT/results/fixture-counts.json"
"$OPENSSL" req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=registry.test -addext 'subjectAltName=DNS:registry.test' -keyout "$RUNTIME/key.pem" -out "$RUNTIME/cert.pem" >"$ROOT/results/certificate-generation.log" 2>&1
chmod 600 "$RUNTIME/key.pem"
SOCKET="$RUNTIME/backend.sock"
for f in nginx.conf proxy-common.conf proxy-observe.conf proxy-policy.conf; do
  sed -e "s|@RUNTIME@|$RUNTIME|g" -e "s|@SOCKET@|$SOCKET|g" -e "s|@OBSERVE_PORT@|$OBSERVE_PORT|g" -e "s|@POLICY_PORT@|$POLICY_PORT|g" -e "s|@CERT@|$RUNTIME/cert.pem|g" -e "s|@KEY@|$RUNTIME/key.pem|g" "$ROOT/config/$f.template" > "$RUNTIME/$f"
done
"$PYTHON" "$ROOT/scripts/echo_backend.py" --socket "$SOCKET" --captures "$ROOT/results/backend" > "$ROOT/results/backend.log" 2>&1 & BACKEND_PID=$!
for _ in $(seq 1 100); do [[ -S "$SOCKET" ]] && break; sleep .02; done
[[ -S "$SOCKET" ]]
"$NGINX" -e stderr -t -c "$RUNTIME/nginx.conf" > "$ROOT/results/nginx-test.log" 2>&1
"$NGINX" -e stderr -c "$RUNTIME/nginx.conf" > "$ROOT/results/nginx-stdout.log" 2>&1 & NGINX_PID=$!
"$PYTHON" - "$OBSERVE_PORT" "$POLICY_PORT" <<'PY'
import socket,sys,time
for port in map(int,sys.argv[1:]):
 for _ in range(100):
  try:s=socket.create_connection(('127.0.0.1',port),.1);s.close();break
  except OSError:time.sleep(.02)
 else:raise SystemExit('listener not ready: '+str(port))
PY
"$PYTHON" "$ROOT/scripts/h1_client.py" --cases "$ROOT/fixtures/h1-cases.json" --out "$ROOT/results/h1-observe" --port "$OBSERVE_PORT" --mode observe
"$PYTHON" "$ROOT/scripts/h1_client.py" --cases "$ROOT/fixtures/h1-cases.json" --out "$ROOT/results/h1-policy" --port "$POLICY_PORT" --mode policy
"$PYTHON" "$ROOT/scripts/h2_client.py" --cases "$ROOT/fixtures/h2-cases.json" --out "$ROOT/results/h2-observe" --port "$OBSERVE_PORT" --mode observe
"$PYTHON" "$ROOT/scripts/h2_client.py" --cases "$ROOT/fixtures/h2-cases.json" --out "$ROOT/results/h2-policy" --port "$POLICY_PORT" --mode policy
NGINX_OUT=$(dirname "$(dirname "$NGINX")")
PYTHON_OUT=$(dirname "$(dirname "$PYTHON")")
OPENSSL_OUT=$(dirname "$(dirname "$OPENSSL")")
{
  printf 'nginxOut=%s\n' "$NGINX_OUT"
  printf 'nginxDrv=%s\n' "$(nix-store --query --deriver "$NGINX_OUT")"
  printf 'nginxBinSha256=%s\n' "$(sha256sum "$NGINX" | cut -d' ' -f1)"
  printf 'effectiveNginxConfigSha256=%s\n' "$(sha256sum "$RUNTIME/nginx.conf" | cut -d' ' -f1)"
  printf 'nginxTemplateSha256=%s\n' "$(sha256sum "$ROOT/config/nginx.conf.template" | cut -d' ' -f1)"
  printf 'backendSocket=%s\n' 'AF_UNIX loopback-private'
  printf 'backendSocketMode=%s\n' "$(stat -c %a "$SOCKET")"
  printf 'backendSocketUid=%s\n' "$(stat -c %u "$SOCKET")"
  printf 'certificateSha256=%s\n' "$("$OPENSSL" x509 -in "$RUNTIME/cert.pem" -outform DER | sha256sum | cut -d' ' -f1)"
  printf 'pythonH2Out=%s\n' "$PYTHON_OUT"
  printf 'pythonH2Drv=%s\n' "$(nix-store --query --deriver "$PYTHON_OUT")"
  printf 'opensslOut=%s\n' "$OPENSSL_OUT"
  printf 'opensslDrv=%s\n' "$(nix-store --query --deriver "$OPENSSL_OUT")"
  "$NGINX" -V 2>&1 | sed 's/^/nginxV=/' | sed 's/[[:space:]]*$//'
  "$PYTHON" - <<'PY'
import h2,hpack,hyperframe,ssl,sys
print('pythonVersion='+sys.version.replace('\n',' '))
print('pythonSSL='+ssl.OPENSSL_VERSION)
print('h2Version='+h2.__version__)
print('hpackVersion='+hpack.__version__)
print('hyperframeVersion='+hyperframe.__version__)
PY
  "$OPENSSL" version | sed 's/^/certificateGenerator=/'
} > "$ROOT/results/toolchain.txt"
