import json
import os
import re
import urllib.parse


import redis
from requests_oauthlib import OAuth1Session
import yaml

import flask
from flask import Flask, request
from flask_cors import cross_origin

app = Flask(__name__)
logger = app.logger
r = redis.StrictRedis()


# Utility functions


def format_url(template, url):
    parts = urllib.parse.urlsplit(url)
    return template.format(**parts._asdict())


def get_origin(request):
    origin = (request.referrer
              or request.headers.get('origin')
              or request.args.get('d')
              or request.args.get('redirect_uri')
             )
    origin_parts = urllib.parse.urlsplit(origin)
    return format_url('{scheme}://{netloc}/', origin)


# Models


class Client:
    # Temporarily using a file
    _this_dir = os.path.dirname(__file__)
    keystore = yaml.load(open(os.path.join(_this_dir, 'clients.yaml')))
    def __init__(self, app_key):
        # The app_key is what goes in OAuth.initialize() on the frontend.
        credentials = self.keystore[app_key]
        self.key = credentials['key']
        self.secret = credentials['secret']


class Sites:
    class Site:
        def __init__(self, request_token_url, authorization_url,
                     access_token_url, **kwargs):
            self.request_token_url = request_token_url
            self.authorization_url = authorization_url
            self.access_token_url = access_token_url
            self.extra_params = kwargs

    @classmethod
    def get(cls, provider):
        return getattr(cls, provider)

    @classmethod
    def all(cls):
        return [s for s in dir(cls) if isinstance(s, cls.Site)]

    twitter = Site('https://api.twitter.com/oauth/request_token',
                   'https://api.twitter.com/oauth/authenticate',
                   'https://api.twitter.com/oauth/access_token',
                  )


class Sessions:
    expiry = 600
    key_template = 'ahoy:session:%s'

    @staticmethod
    def _serialize(obj):
        return json.dumps(obj).encode('utf8')

    @staticmethod
    def _deserialize(obj_str):
        return json.loads(obj_str.decode('utf8'))

    @classmethod
    def put(cls, request, request_token):
        opts = json.loads(request.args['opts'])
        key = cls.key_template % opts['state']

        session_data = {
            'client': request.args['k'],
            'origin': get_origin(request),
            'provider': request.view_args['provider'],
            'resource_owner_key': request_token['oauth_token'],
            'resource_owner_secret': request_token['oauth_token_secret'],
            }

        r.setex(key, cls.expiry, cls._serialize(session_data))
        return session_data

    @classmethod
    def get(cls, state):
        key = cls.key_template % state
        session_bytes = r.get(key)
        if session_bytes is None:
            raise KeyError('Session invalid or expired')
        return cls._deserialize(session_bytes)

    @classmethod
    def delete(cls, state):
        key = cls.key_template % state
        return r.delete(key)


# Routes


@app.route('/')
def hello_world():
    return 'Hello, World!'


@app.route('/api/extended-endpoints')
@cross_origin('*')
def api_extended_endpoints():
    response = {'status': 'success', 'data': []}
    return flask.jsonify(response)


@app.route('/auth/iframe')
def iframe_inject():
    def _escape(in_str):
        out_str = re.sub(r'[\/"\']', r'\$&', in_str)
        out_str = re.sub('\u0000', r'\0', out_str)
        return out_str
    origin = _escape(get_origin(request))
    return flask.render_template('iframe_inject.html', origin=origin)


@app.route('/auth/<provider>')
def initiate_auth(provider):
    # TODO: Enforce domain is allowed in /auth/:provider
    opts = json.loads(request.args['opts'])
    state = opts['state']
    callback_query = urllib.parse.urlencode({'state': state})
    callback_uri = '{scheme}://{host}:{port}/auth?{query}'.format(
        scheme=SCHEME, host=HOST, port=PORT, query=callback_query)
    client = Client(request.args['k'])
    oauth = OAuth1Session(
        client.key,
        client_secret=client.secret,
        callback_uri=callback_uri,
        )
    site = Sites.get(provider)
    request_token = oauth.fetch_request_token(site.request_token_url)
    Sessions.put(request, request_token)

    auth_url = oauth.authorization_url(site.authorization_url,
                                       **site.extra_params)
    return flask.redirect(auth_url, code=302)


@app.route('/auth')
def fetch_tokens():
    state = request.args['state']
    try:
        session_data = Sessions.get(state)
    except KeyError:
        return ('Invalid format<br/>'
                '<span style="color:red">state</span>:'
                'invalid or expired<br/>')
    provider = session_data['provider']
    site = Sites.get(provider)
    client = Client(session_data['client'])

    oauth = OAuth1Session(
        client.key,
        client_secret=client.secret,
        resource_owner_key=session_data['resource_owner_key'],
        resource_owner_secret=session_data['resource_owner_secret'],
        verifier=request.args['oauth_verifier'],
        )
    oauth_tokens = oauth.fetch_access_token(site.access_token_url)
    Sessions.delete(state)

    origin = session_data['origin']
    user_agent = request.headers['user-agent']
    is_ie = user_agent.startswith('IE')
    chrome_rex = re.match(r'chrome-extension://([^\/]+)', user_agent)
    chrome_ext = chrome_rex.group(1) if chrome_rex else None
    request_url = format_url('{scheme}://{netloc}', site.access_token_url)

    response_body = {
        'data': {
            'oauth_token': oauth_tokens['oauth_token'],
            'oauth_token_secret': oauth_tokens['oauth_token_secret'],
            'request': {
                'url': request_url
            }
        },
        'provider': provider,
        'state': state,
        'status': 'success',
    }
    context = {
        'origin': origin,
        'user_agent': user_agent,
        'is_ie': is_ie,
        'chrome_ext': chrome_ext,
        'body': response_body,
    }

    response = flask.render_template('client_callback.html', **context)
    if is_ie:
        response.headers['p3p'] = ('CP="IDC DSP COR ADM DEVi TAIi PSA PSD'
                                   ' IVAi IVDi CONi HIS OUR IND CNT"')
    return response


if __name__ == '__main__':
    # TODO: argparse
    SCHEME = 'http'
    HOST = 'localhost'
    PORT = 6285
    app.run(debug=True, host=HOST, port=PORT)
