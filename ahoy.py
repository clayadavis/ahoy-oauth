import json
import re
import urllib.parse


import redis
from requests_oauthlib import OAuth1Session

import flask
from flask import Flask, request
from flask_cors import cross_origin

app = Flask(__name__)
logger = app.logger

try:
    import local_settings
except ImportError:
    logger.warn('No local_settings.py found; using default settings')
    import types
    local_settings = types.SimpleNamespace()


REDIS_HOST = getattr(local_settings, 'REDIS_HOST', 'localhost')
REDIS_PORT = getattr(local_settings, 'REDIS_PORT', 6379)
REDIS_DB   = getattr(local_settings, 'REDIS_DB', 0)
r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB)


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
    return format_url('{scheme}://{netloc}/', origin)

def _serialize(obj):
    return json.dumps(obj).encode('utf8')

def _deserialize(obj_str):
    return json.loads(obj_str.decode('utf8'))


# Models


class Client:
    _redis_key = 'ahoy:clients'
    def __init__(self, app_id, key, secret, **extra):
        # The app_id is what goes in OAuth.initialize() on the frontend.
        # These are required to have

        self.id = app_id
        self.key = key
        self.secret = secret
        for k, v in extra.items():
            setattr(self, k, v)

    def __repr__(self):
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    def __str__(self):
        return "<%s '%s'>" % (type(self).__name__, self.id)

    def delete(self):
        return r.hdel(self._redis_key, self.id)

    def save(self):
        data = self.to_dict()
        del data['id']
        return r.hset(self._redis_key, self.id, _serialize(data))

    def to_dict(self):
        obj = {}
        for k in dir(self):
            if not k.startswith('_'):
                v = getattr(self, k)
                if not callable(v):
                    obj[k] = v
        return obj

    @classmethod
    def get(cls, app_id):
        data = r.hget(cls._redis_key, app_id)
        if data is None:
            raise KeyError('Invalid app ID')
        return cls(app_id, **_deserialize(data))

    @classmethod
    def all(cls, as_dict=False):
        def _clients():
            for k, v in r.hgetall(cls._redis_key).items():
                key = k.decode('utf8')
                val = cls(key, **_deserialize(v))
                yield key, val
        if as_dict:
            return dict(_clients())
        else:
            return [v for k, v in _clients()]


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
        attrs = [getattr(cls, s) for s in dir(cls)]
        return [a for a in attrs if isinstance(a, cls.Site)]

    twitter = Site('https://api.twitter.com/oauth/request_token',
                   'https://api.twitter.com/oauth/authenticate',
                   'https://api.twitter.com/oauth/access_token',
                  )


class Sessions:
    expiry = 600
    key_template = 'ahoy:session:%s'

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

        r.setex(key, cls.expiry, _serialize(session_data))
        return session_data

    @classmethod
    def get(cls, state):
        key = cls.key_template % state
        session_bytes = r.get(key)
        if session_bytes is None:
            raise KeyError('Session invalid or expired')
        return _deserialize(session_bytes)

    @classmethod
    def delete(cls, state):
        key = cls.key_template % state
        return r.delete(key)


# Routes


@app.route('/')
def hello_world():
    return 'Ahoy!'


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
    callback_path = '/auth'
    try:
        callback_uri = '{root}{path}?{query}'.format(
                root=local_settings.CALLBACK_URL_ROOT,
                path=callback_path,
                query=callback_query,
                )
    except AttributeError:
        callback_uri = '{scheme}://{host}:{port}/auth?{query}'.format(
                scheme=SCHEME, host=HOST, port=PORT, query=callback_query)
    client = Client.get(request.args['k'])
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
    client = Client.get(session_data['client'])

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
