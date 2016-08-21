import json
import unittest

import requests

import ahoy

SERVER_ADDRESS = 'http://localhost:6285'


class Requester:
    def get(*args, **kwargs):
        return requests.get(*args, **kwargs)


class TestAPI(unittest.TestCase):
    requester = Requester()

    @staticmethod
    def get_url(method):
        return '/'.join(x for x in [SERVER_ADDRESS, 'api', method] if x)

    def test_extended_endpoints(self):
        url = self.get_url('extended-endpoints')
        expected_response = {'status': 'success', 'data': []}
        resp = requests.get(url)
        self.assertEqual(resp.status_code, 200)
        self.assertDictEqual(resp.json(), expected_response)


class TestAuth(unittest.TestCase):
    requester = Requester()

    @staticmethod
    def get_url(method):
        return '/'.join(x for x in [SERVER_ADDRESS, 'auth', method] if x)

    def test_auth_initiation(self):
        url = self.get_url('twitter')
        params = {
            'd': 'http://localhost:8000/',
            'k': 'vJhoKxN6ZRlJ4vyumPlzk6xjzZA',
            'opts': json.dumps({
                'state': 'xFt4m88cvCCITFbxoNgoJiymvlU',
                'state_type': 'client',
                }),
            }
        resp = requests.get(url, params=params, allow_redirects=False)
        self.assertEqual(resp.status_code, 302)


class TestSites(unittest.TestCase):
    sites = ahoy.Sites.all()

    def test_urls(self):
        for site in self.sites:
            for attr in ['request_token_url', 'authorization_url',
                    'access_token_url']:
                getattr(site, attr)


if __name__ == '__main__':
    unittest.main()
