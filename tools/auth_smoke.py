import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]


def b64(value):
    return base64.urlsafe_b64encode(value).decode().rstrip('=')


def request(url, method='GET', data=None, token=None, form=False, status=200, headers=None):
    headers = dict(headers or {})
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if data is not None:
        headers['Content-Type'] = 'application/x-www-form-urlencoded' if form else 'application/json'
        data = (urlencode(data) if form else json.dumps(data)).encode()
    try:
        response = urlopen(Request(url, data=data, headers=headers, method=method), timeout=20)
    except HTTPError as error:
        response = error
    with response:
        body = response.read()
        assert response.status == status, f'{method} expected HTTP {status}, received {response.status}: {body.decode()}'
        return json.loads(body) if body else None


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class IdentityProvider:
    def __init__(self, directory):
        self.directory = directory
        self.key = directory / 'rsa.pem'
        self.public = directory / 'rsa-public.pem'
        subprocess.run(['openssl', 'genrsa', '-out', str(self.key), '2048'], check=True, capture_output=True)
        subprocess.run(['openssl', 'rsa', '-in', str(self.key), '-pubout', '-out', str(self.public)], check=True, capture_output=True)
        modulus = subprocess.check_output(['openssl', 'rsa', '-in', str(self.key), '-modulus', '-noout'], stderr=subprocess.DEVNULL).decode().strip().split('=')[1]
        self.jwk = dict(kty='RSA', use='sig', alg='RS256', kid='one', n=b64(bytes.fromhex(modulus)), e='AQAB')
        self.secret = secrets.token_urlsafe(32)
        self.active = True
        self.requests = []
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                provider.requests.append(self.path)
                if self.path == '/.well-known/openid-configuration':
                    value = dict(issuer=provider.issuer, jwks_uri=provider.issuer + '/keys', token_endpoint=provider.issuer + '/token')
                elif self.path == '/keys':
                    value = dict(keys=[provider.jwk])
                else:
                    self.send_error(404)
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(value).encode())

            def do_POST(self):
                provider.requests.append(self.path)
                form = parse_qs(self.rfile.read(int(self.headers['Content-Length'])).decode())
                if self.path == '/token' and form.get('client_id') == ['external-client'] and form.get('client_secret') == [provider.secret]:
                    value = dict(access_token=provider.jwt(), token_type='Bearer', expires_in=60)
                elif self.path == '/introspect' and self.headers.get('Authorization') == 'Basic ' + base64.b64encode(('catalog:' + provider.secret).encode()).decode():
                    value = provider.claims() | dict(active=provider.active and form.get('token') == ['opaque-token'])
                else:
                    self.send_error(401)
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(value).encode())

        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.issuer = f'http://127.0.0.1:{self.server.server_port}'
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def claims(self):
        return dict(iss=self.issuer, aud='catalog', exp=int(time.time()) + 60, sub='external-user', realm_access={'roles': ['orchid_reader', 'ignored']})

    def jwt(self, **overrides):
        header = b64(json.dumps(dict(alg='RS256', typ='JWT', kid=self.jwk['kid'])).encode())
        payload = b64(json.dumps(self.claims() | overrides).encode())
        data = (header + '.' + payload).encode()
        signature = subprocess.check_output(['openssl', 'dgst', '-sha256', '-sign', str(self.key)], input=data)
        return data.decode() + '.' + b64(signature)


def seed(url, scope, token):
    fixture = json.loads((ROOT / 'examples/social.json').read_text())
    objects = {key: fixture['objects'][key] for key in ('people', 'person')}
    objects['person']['mapping']['properties']['id'] = 'id'
    objects['peer'] = dict(kind='cypher_relationship', name='PEER', parameters=[dict(name='score', schema=dict(type='integer'), default=0), dict(name='limit', schema=dict(type='integer', minimum=1), default=100)], source='person', target='person', description='Other people', cypher='WITH source MATCH (target:Person) WHERE target.id <> source.id AND target.id >= $score RETURN target, target.id AS rank ORDER BY rank DESC LIMIT $limit', returns=dict(target='target', properties=dict(rank=dict(type='integer'))))
    for id, definition in objects.items():
        request(f'{url}/v1/{scope}/objects/{id}', 'PUT', dict(expected_version=0, definition=definition), token)
    request(f'{url}/v1/{scope}/graphs/smoke', 'PUT', dict(expected_version=0, definition=dict(description='Auth smoke graph', objects=['person', 'peer'])), token)
    request(f'{url}/v1/{scope}/graphs/smoke/grants', 'PUT', dict(expected_version=0, definition=dict(discover=['reader'], execute=['reader'])), token)
    request(f'{url}/v1/{scope}/graphs/smoke/publish', 'POST', dict(expected_revision=0, graph_version=1, object_versions={key: 1 for key in objects}), token)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server', type=Path, default=ROOT / 'target/debug/orchid-catalog')
    parser.add_argument('--clients', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='orchid-auth-smoke-') as temporary:
        directory = Path(temporary)
        subprocess.run([str(args.server), 'bootstrap', str(directory / 'secrets')], check=True, stdout=subprocess.DEVNULL)
        provider = IdentityProvider(directory)
        path = directory / 'secrets/auth.json'
        config = json.loads(path.read_text())
        internal = config['default']['internal']
        internal['token_lifetime_seconds'] = 120
        external = dict(issuer=provider.issuer, audience='catalog', roles_claim='realm_access/roles', role_filter='^orchid_.*$', role_mappings=[dict(regex='^orchid_(.*)$', replacement='$1')], require_registered_principal=False)
        config['default'] = dict(mode='mixed', internal=internal, external=external)
        config['scopes'] = {
            'rsa': dict(mode='internal', internal=internal | dict(signing=dict(type='rsa', private_key_file=str(provider.key), public_key_file=str(provider.public)))),
            'external': dict(mode='external', external=external),
            'registered': dict(mode='mixed', internal=internal, external=external | dict(require_registered_principal=True)),
            'opaque': dict(mode='mixed', internal=internal, external=external | dict(introspection=dict(endpoint=provider.issuer + '/introspect', client_id='catalog', client_secret_env='SMOKE_IDP_SECRET'))),
            'renew': dict(mode='internal', internal=internal | dict(token_lifetime_seconds=8)),
        }
        path.write_text(json.dumps(config))
        secret = (directory / 'secrets/admin.secret').read_text()
        url = f'http://127.0.0.1:{port()}'
        environment = os.environ | dict(ORCHID_CATALOG_AUTH_CONFIG=str(path), ORCHID_CATALOG_DATABASE='sqlite://' + str(directory / 'catalog.db') + '?mode=rwc', ORCHID_CATALOG_LISTEN=url.removeprefix('http://'), SMOKE_IDP_SECRET=provider.secret)
        log = (directory / 'server.log').open('w+')
        process = subprocess.Popen([str(args.server)], env=environment, stdout=log, stderr=log)
        try:
            for _ in range(100):
                if process.poll() is not None:
                    log.seek(0)
                    raise AssertionError('catalog startup failed: ' + log.read())
                try:
                    request(url + '/healthz')
                    break
                except OSError:
                    time.sleep(0.05)
            else:
                raise AssertionError('catalog startup timed out')

            def issue(scope='smoke', id='admin', credential=secret, roles='PRINCIPAL_ROLE:ALL', status=200):
                return request(f'{url}/v1/{scope}/oauth/tokens', 'POST', dict(grant_type='client_credentials', client_id=id, client_secret=credential, scope=roles), form=True, status=status)

            admin = issue()['access_token']
            assert issue(credential='wrong', status=401) == issue(id='missing', status=401)
            basic = 'Basic ' + base64.b64encode(('admin:' + secret).encode()).decode()
            request(url + '/v1/smoke/oauth/tokens', 'POST', dict(grant_type='client_credentials', scope='PRINCIPAL_ROLE:ALL'), form=True, headers={'Authorization': basic})
            seed(url, 'smoke', admin)
            request(url + '/v1/smoke/graphs/smoke/discover', status=401)
            request(url + '/v1/smoke/graphs/smoke/discover', token=admin)
            request(url + '/v1/other/graphs/smoke/discover', token=admin, status=401)
            request(url + '/v1/smoke/schema', token=admin)
            created = request(url + '/v1/smoke/principals/workload', 'PUT', dict(expected_version=0, definition=dict(principal=dict(subject='workload', roles=['reader']))), admin)
            worker = issue(id='workload', credential=created['client_secret'])['access_token']
            request(url + '/v1/smoke/graphs/smoke/discover', token=worker)
            request(url + '/v1/smoke/principals', token=worker, status=403)
            no_roles = issue(id='workload', credential=created['client_secret'], roles='')['access_token']
            missing = request(url + '/v1/smoke/graphs/missing/discover', token=no_roles, status=404)
            assert request(url + '/v1/smoke/graphs/smoke/discover', token=no_roles, status=404) == missing
            issue(id='workload', credential=created['client_secret'], roles='PRINCIPAL_ROLE:service_admin', status=401)
            exchanged = request(url + '/v1/smoke/oauth/tokens', 'POST', dict(grant_type='urn:ietf:params:oauth:grant-type:token-exchange', subject_token=worker, subject_token_type='urn:ietf:params:oauth:token-type:access_token', scope='PRINCIPAL_ROLE:reader'), form=True)['access_token']
            request(url + '/v1/smoke/graphs/smoke/discover', token=exchanged)
            public = request(url + '/v1/smoke/principals/workload', token=admin)
            assert 'secret_sha256' not in json.dumps(public)
            rotated = request(url + '/v1/smoke/principals/workload', 'PUT', dict(expected_version=1, definition=dict(principal=dict(subject='workload', roles=['reader']))), admin)
            request(url + '/v1/smoke/graphs/smoke/discover', token=worker, status=401)
            issue(id='workload', credential=created['client_secret'], status=401)
            worker = issue(id='workload', credential=rotated['client_secret'])['access_token']
            request(url + '/v1/smoke/principals/workload', 'PUT', dict(expected_version=2, definition=dict(principal=dict(subject='workload', roles=['reader']), enabled=False)), admin)
            request(url + '/v1/smoke/graphs/smoke/discover', token=worker, status=401)
            print('PASS internal OAuth, bearer, role selection, scope isolation, exchange, rotation, disablement', flush=True)

            for scope in ('rsa', 'registered', 'opaque', 'renew'):
                seed(url, scope, issue(scope)['access_token'])
            request(url + '/v1/rsa/graphs/smoke/discover', token=issue('rsa')['access_token'])
            external_token = provider.jwt()
            request(url + '/v1/smoke/graphs/smoke/discover', token=external_token)
            for overrides in (dict(exp=1), dict(aud='wrong'), dict(iss='wrong'), dict(nbf=int(time.time())+120)):
                request(url + '/v1/smoke/graphs/smoke/discover', token=provider.jwt(**overrides), status=401)
            bad = external_token.rsplit('.', 1)[0] + '.' + b64(b'wrong')
            request(url + '/v1/smoke/graphs/smoke/discover', token=bad, status=401)
            request(url + '/v1/external/oauth/tokens', 'POST', dict(grant_type='client_credentials', client_id='admin', client_secret=secret), form=True, status=401)
            registered_admin = issue('registered')['access_token']
            request(url + '/v1/registered/graphs/smoke/discover', token=external_token, status=401)
            request(url + '/v1/registered/principals/external-user', 'PUT', dict(expected_version=0, definition=dict(principal=dict(subject='external-user', roles=['reader']))), registered_admin)
            request(url + '/v1/registered/graphs/smoke/discover', token=external_token)
            request(url + '/v1/opaque/graphs/smoke/discover', token='opaque-token')
            provider.active = False
            request(url + '/v1/opaque/graphs/smoke/discover', token='opaque-token', status=401)
            provider.active = True
            print('PASS RSA, OIDC discovery/JWKS, invalid tokens, mixed mode, registered principals, introspection/revocation', flush=True)

            if args.clients:
                token_file = directory / 'access.token'
                token_file.write_text(admin)
                subprocess.run(args.clients, check=True, env=environment | dict(AUTH_SMOKE_URL=url, AUTH_SMOKE_SECRET=secret, AUTH_SMOKE_SECRET_FILE=str(directory / 'secrets/admin.secret'), AUTH_SMOKE_TOKEN=admin, AUTH_SMOKE_TOKEN_FILE=str(token_file), AUTH_SMOKE_ISSUER=provider.issuer, AUTH_SMOKE_IDP_SECRET=provider.secret, AUTH_SMOKE_DIRECTORY=str(directory)))
            assert all(path in ('/.well-known/openid-configuration', '/keys', '/token', '/introspect') for path in provider.requests)
            config_text = path.read_text()
            path.write_text('{invalid')
            process.send_signal(signal.SIGHUP)
            time.sleep(0.2)
            request(url + '/v1/smoke/graphs/smoke/discover', token=admin, status=401)
            path.write_text(config_text)
            process.send_signal(signal.SIGHUP)
            time.sleep(0.2)
            request(url + '/v1/smoke/graphs/smoke/discover', token=admin)
            log.flush()
            log.seek(0)
            logs = log.read()
            assert secret not in logs and admin not in logs and 'Auth smoke graph' not in logs
            print('PASS fail-closed reload, recovery, metadata/credential log checks', flush=True)
        finally:
            process.terminate()
            process.wait(timeout=10)
            provider.server.shutdown()
            log.close()


if __name__ == '__main__':
    main()
