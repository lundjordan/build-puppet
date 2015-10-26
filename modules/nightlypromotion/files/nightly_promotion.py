#!/usr/bin/env python
import requests
import hashlib
import tempfile
from mardor.marfile import BZ2MarFile
import shutil
import configparser
from functools import partial
import os
import json
from zipfile import ZipFile
import logging
from argparse import ArgumentParser
log = logging.getLogger(__name__)

CONFIGS = []
ARIES_CONFIG = dict(namespace='gecko.v2.mozilla-central.latest.b2g.aries-ota-opt',
                    artifact='public/build/b2g-aries-gecko-update.mar',
                    product='B2G',
                    release='B2G-nightly-latest',
                    platform='aries',
                    locale='en-US',
                    balrog_username='stage-b2gbld',  # TODO - use production username
                    schema_version=4)
B2GDROID_CONFIG = dict(namespace='gecko.v2.mozilla-central.latest.mobile.android-b2gdroid-opt',
                       artifact='public/build/target.apk',
                       product='B2GDroid',
                       branch='mozilla-central',
                       # same as all android build_platforms
                       platform='Android_arm-eabi-gcc3',
                       locale='en-US',
                       balrog_username='ffxbld',
                       schema_version=4)

# TODO - append aries config
CONFIGS.append(B2GDROID_CONFIG)

BALROG_API_ROOT = 'https://aus4-admin.mozilla.org/api'


def sha512sum(filename):
    h = hashlib.new('sha512')
    with open(filename, 'rb') as f:
        for block in iter(partial(f.read, 1024**2), b''):
            h.update(block)
        return h.hexdigest()


def get_mar_info(filename):
    complete_info = {'from': '*'}
    retval = {'completes': [complete_info]}
    complete_info['hashValue'] = sha512sum(filename)
    complete_info['filesize'] = os.path.getsize(filename)
    mar = BZ2MarFile(filename)

    for m in mar.members:
        if m.name.endswith("platform.ini") or m.name.endswith("application.ini"):
            # Extract it!
            tmpdir = tempfile.mkdtemp()
            try:
                ini = mar.extract(m, tmpdir)
                conf = configparser.RawConfigParser()
                conf.read([ini])
                if m.name == 'platform.ini':
                    retval['platformVersion'] = conf.get('Build', 'Milestone')
                else:
                    retval['appVersion'] = conf.get('App', 'Version')
                    retval['displayVersion'] = conf.get('App', 'Version')
                    retval['buildID'] = conf.get('App', 'BuildID')
            finally:
                shutil.rmtree(tmpdir)

    return retval


def get_apk_info(filename):
    complete_info = {'from': '*'}
    retval = {'completes': [complete_info]}
    complete_info['hashValue'] = sha512sum(filename)
    complete_info['filesize'] = os.path.getsize(filename)
    apk = ZipFile(filename)

    for z in apk.infolist():
        if z.filename.endswith("platform.ini") or z.filename.endswith("application.ini"):
            # Extract it!
            tmpdir = tempfile.mkdtemp()
            try:
                ini = apk.extract(z, tmpdir)
                conf = configparser.RawConfigParser()
                conf.read([ini])
                if z.filename == 'platform.ini':
                    retval['platformVersion'] = conf.get('Build', 'Milestone')
                else:
                    retval['appVersion'] = conf.get('App', 'Version')
                    retval['displayVersion'] = conf.get('App', 'Version')
                    retval['buildID'] = conf.get('App', 'BuildID')
            finally:
                shutil.rmtree(tmpdir)

    return retval


def get_file_info(url):
    s = 0
    r = requests.get(url, stream=True)
    expected_size = int(r.headers['Content-Length'])
    with tempfile.NamedTemporaryFile() as tmp:
        for block in r.iter_content(1024**2):
            s += len(block)
            tmp.write(block)
        tmp.flush()
        assert expected_size == s

        if url.endswith(".mar"):
            info = get_mar_info(tmp.name)
            info['completes'][0]['fileUrl'] = url
            return info
        elif url.endswith(".apk"):
            info = get_apk_info(tmp.name)
            info['completes'][0]['fileUrl'] = url
            return info


class TCIndex:
    api_root = 'https://index.taskcluster.net/v1'

    def get_artifact_url(self, namespace, filename):
        url = '{}/task/{}/artifacts/{}'.format(self.api_root, namespace, filename)
        return requests.get(url, allow_redirects=False).headers['Location']


class Balrog:
    auth = ()

    def get_auth(self, username, auth_file=None):
        if self.auth:
            return self.auth

        auth_file = auth_file or 'credentials.py'
        if not os.path.exists(auth_file):
            log.error(
                'Could not determine path to balrog credentials. Does "{}" exist?'.format(auth_file)
            )

        credentials = {}
        execfile(auth_file, credentials)
        self.auth = (username, credentials['balrog_credentials'][username])
        return self.auth

    def update_release(self, product, schema_version, api, info, balrog_username, auth_file):
        session = requests.session()

        data = {
            'product': product,
            'version': info['appVersion'],
            'hashFunction': 'sha512',
            'schema_version': schema_version,
        }
        data['data'] = json.dumps(info)

        # Get the old release - we need the old data_version and csrf token
        resp = session.head(api, auth=self.get_auth(balrog_username, args.auth_file))
        if resp.status_code == 200:
            log.info('previous release found; updating')
            data['data_version'] = resp.headers['X-Data-Version']
            data['csrf_token'] = resp.headers['X-CSRF-Token']
        elif resp.status_code == 404:
            log.info('previous release not found; creating a new one')
            # Get a new csrf token
            resp = session.head("{}/csrf_token".format(BALROG_API_ROOT),
                                auth=self.get_auth(balrog_username, args.auth_file))
            resp.raise_for_status()
            data['csrf_token'] = resp.headers['X-CSRF-Token']
        else:
            resp.raise_for_status()

        resp = session.put(api, auth=self.get_auth(balrog_username, args.auth_file), data=data)
        resp.raise_for_status()


def load_cache(filename=None):
    if not filename:
        filename = 'cache.json'
    try:
        return json.load(open(filename))
    except IOError:
        return {}


def save_cache(cache, filename=None):
    if not filename:
        filename = 'cache.json'
    with open(filename, 'w') as f:
        json.dump(cache, f, indent=2)


def main(args):
    log_file = args.log_file or 'nightly_promotion.log'
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s", filename=log_file)
    balrog = Balrog()
    index = TCIndex()

    log.info('loading cache')
    cache = load_cache(filename=args.cache_file)
    log.debug('cache: %s', cache)

    for c in CONFIGS:
        log.info('finding latest %s %s', c['namespace'], c['artifact'])
        url = index.get_artifact_url(c['namespace'], c['artifact'])
        log.info('got url: %s', url)
        cache_key = '{c[namespace]}:{c[artifact]}'.format(c=c)
        if cache.get(cache_key) == url:
            log.info('unchanged url; skipping')
            continue
        cache[cache_key] = url
        log.info('downloading...')
        info = get_file_info(url)

        log.info('updating balrog: %s', info)
        # submit this release then update 'latest' channel to point to it
        for blob in [info['buildID'], 'latest']:
            api = '{}/releases/{}-{}-nightly-{}/builds/{}/{}'.format(
                BALROG_API_ROOT, c['product'], c['branch'], blob, c['platform'], c['locale']
            )
            balrog.update_release(c['product'], c['schema_version'], api, info,
                                  c['balrog_username'], args.auth_file)

    log.info('saving cache')
    log.debug('cache: %s', cache)
    save_cache(cache, args.cache_file)

if __name__ == '__main__':
    parser = ArgumentParser(description='Process some integers.')
    parser.add_argument('log_file', help='path of log file')
    parser.add_argument('cache_file', help='path of cache file ')
    parser.add_argument('auth_file', help='path of auth file ')
    args = parser.parse_args()
    main(args)

