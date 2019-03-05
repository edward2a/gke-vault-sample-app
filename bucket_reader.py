#!/usr/bin/env python3

import argparse
import falcon
import json
import requests

from types import SimpleNamespace
from wsgiref.simple_server import make_server


class AuthManager():
    # TODO: Token expiration tracking
    # TODO: Token renew prior to expiration

    gcp_jwt = None # The one for using GCP services (obtained from Vault)
    k8s_jwt = None # The one used to login to vault (obtained from k8s)

    k8s_token_path = '/var/run/secrets/kubernetes.io/serviceaccount/token'

    vault_host = None
    vault_token = None
    vault_k8s_path = 'auth/kubernetes/login'
    vault_k8s_role = None

    vault_gcp_path = 'gcp/token'
    vault_gcp_role = None

    def __init__(self, args):
        # fetch kubernetes secret
        # authenticate against vault
        # request vault role jwt and store it

        self.vault_host = 'https://' + args.vault_host
        self.vault_k8s_role = args.vault_kube_role
        self.vault_gcp_role = args.vault_gcp_role

        self.get_container_secret()
        self.get_vault_auth()
        self.get_gcp_auth_from_vault()

    def get_container_secret(self):
        """Retrive the k8s SA secret from default path."""
        with open(self.k8s_token_path) as f:
            self.k8s_jwt = f.read().strip()

    def get_vault_auth(self):
        """Authenticate against Vault with k8s SA secret."""
        data = {
            "role": self.vault_k8s_role,
            "jwt": self.k8s_jwt
        }

        url = '{}/v1/{}'.format(self.vault_host, self.vault_k8s_path)

        # NOTE: verify=False is for self-signed SSL certs, NOT FOR PROD
        r = requests.post(url=url, verify=False, json=data)
        # TODO: handle errors
        self.vault_token = r.json()['auth']['client_token']

    def get_gcp_auth_from_vault(self):
        """Get a temporary GCP token from Vault."""
        url = '{}/v1/{}/{}'.format(self.vault_host, self.vault_gcp_path, self.vault_gcp_role)

        headers = {
            'X-Vault-Token': self.vault_token
        }

        # NOTE: verify=False is for self-signed SSL certs, NOT FOR PROD
        r = requests.get(url=url, headers=headers, verify=False)
        # TODO: handle errors
        self.gcp_jwt = r.json()['data']['token']


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


def get_arguments():
    p = argparse.ArgumentParser()
    p.add_argument('-t', '--token', required=False, default=None,
        help='JWT token - use for troubleshooting')
    p.add_argument('-v', '--vault-host', required=True,
        help='Vault endpoint (IP address, no scheme)')
    p.add_argument('-k', '--vault-kube-role', required=True,
        help='Vault role for the kubernetes authentication engine')
    p.add_argument('-g', '--vault-gcp-role', required=True,
        help='Vault role for the gcp secret engine')
    return p.parse_args()

if __name__ == "__main__":

    args = get_arguments()

    if args.token:
        auth = SimpleNamespace()
        auth.gcp_jwt = args.token
    else:
        auth = AuthManager(args)

    handler = SyncHandlerGCS(auth.gcp_jwt)

    api = falcon.API()
    api.add_route('/{bucket}', ObjectReader(handler))
    api.add_route('/{bucket}/{obj}', ObjectReader(handler))

    with make_server('127.0.0.1', 8000, api) as httpd:
        print('Serving on 127.0.0.1:8000...')
        httpd.serve_forever()
