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
        # Probably need to add a test Client instead of assuming this one will
        # be there
        params = {
            'd': 'http://localhost:8000/',
            'k': 'vJhoKxN6ZRlJ4vyumPlzk6xjzZA',
            'opts': json.dumps({
                # state is arbitrary, although should be the same length
                'state': 'xFt4m88cvCCITFbxoNgoJiymvlU',
                'state_type': 'client',
                }),
            }
        resp = requests.get(url, params=params, allow_redirects=False)
        self.assertEqual(resp.status_code, 302)


class TestModels(unittest.TestCase):
    sites = ahoy.Sites.all()

    def test_sites(self):
        for site in ahoy.Sites.all():
            for attr in ['request_token_url', 'authorization_url',
                    'access_token_url']:
                getattr(site, attr)

    def test_clients(self):
        client = ahoy.Client('test', 'testkey', 'testsecret',
                             name='Test Client')
        try:
            self.assertTrue(client.save())
            client.key = 'testkeychanged'
            self.assertFalse(client.save())
            client.testattr = 'testtest'
            self.assertFalse(client.save())

            newclient = ahoy.Client.get(client.id)
            self.assertDictEqual(newclient.to_dict(), client.to_dict())
        finally:
            self.assertTrue(client.delete())


if __name__ == '__main__':
    unittest.main()
