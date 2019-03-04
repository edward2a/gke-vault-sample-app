#!/usr/bin/env python3

import argparse
import falcon
import json
import requests

from types import SimpleNamespace
from wsgiref.simple_server import make_server


class AuthManager():

    jwt = None

    def __init__(self):
        pass
        # fetch kubernetes secret
        # authenticate against vault
        # request vault role jwt and store it

    def get_container_secret(self):
        pass

    def get_vault_auth(self):
        pass

    def get_gcp_auth_from_vault(self):
        pass


class SyncHandlerGCS():

    def __init__(self, signed_jwt):
       self.signed_jwt = signed_jwt

    def make_jwt_request(self, url):
        """Makes an authorized request to the endpoint"""
        headers = {
            'Authorization': 'Bearer {}'.format(self.signed_jwt),
            'content-type': 'application/json'
        }
        response = requests.get(url, headers=headers)

        response.raise_for_status()
        return response.text


class ObjectReader():

    base_url = 'https://www.googleapis.com/storage/v1/b/'

    def __init__(self, gcs):
        self.gcs = gcs

    def url_constructor(self, bucket, obj=None):
        url = self.base_url + bucket

        if obj:
            url += '/o/' + obj

        return url

    def on_get(self, req, resp, bucket=None, obj=None):
        if obj:
            obj_location = json.loads(
                self.gcs.make_jwt_request(self.url_constructor(
                    bucket, obj)))['mediaLink']
            resp.media = self.gcs.make_jwt_request(obj_location)
        else:
            resp.media = self.gcs.make_jwt_request(
                self.url_constructor(bucket, obj))


if __name__ == "__main__":

    p = argparse.ArgumentParser()
    p.add_argument('-t', '--token', required=False, default=None,
        help='JWT token - use for troubleshooting')
    args = p.parse_args()

    if args.token:
        auth = SimpleNamespace()
        auth.jwt = args.token
    else:
        auth = AuthManager()

    handler = SyncHandlerGCS(auth.jwt)

    api = falcon.API()
    api.add_route('/{bucket}', ObjectReader(handler))
    api.add_route('/{bucket}/{obj}', ObjectReader(handler))

    with make_server('127.0.0.1', 8000, api) as httpd:
        print('Serving on 127.0.0.1:8000...')
        httpd.serve_forever()
