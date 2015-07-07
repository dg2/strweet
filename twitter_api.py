import base64
import logging
import json
from ConfigParser import ConfigParser
from urlparse import urljoin

import requests
import dateutil.parser as parser
from skimage import io
from requests_oauthlib import OAuth1Session

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(message)s')

OAUTH2_TOKEN_URL = "https://api.twitter.com/oauth2/token"
REQUEST_TOKEN_URL = "https://api.twitter.com/oauth/request_token"
BASE_AUTHORIZATION_URL = 'https://api.twitter.com/oauth/authorize'
API_VERSION = "1.1"


class FailedAPICall(Exception):
    pass


class AuthenticationLevelError(Exception):
    pass


class User:
    def __init__(self, data):
        self.data = data
        self.status = Tweet(data['status'])

    def get_profile_img(self):
        return io.imread(self.data['profile_image_url'])

    def get_background_img(self):
        return io.imread(self.data['profile_background_image_url'])

    def created_at(self):
        return parser.parse(self.data['created_at'])


class Tweet:
    def __init__(self, data):
        self.data = data
        self.user = User(data['user']) if 'user' in data else None


class Entities:
    pass


class Media:
    pass


class Symbol:
    pass


class URL:
    pass


class UserMention:
    pass


def flatten(it):
    '''
    Flattens a generator
    '''
    for x in it:
        if (isinstance(x, list) and not isinstance(x, str)):
            for y in flatten(x):
                yield y
        else:
            yield x


class MessageTypes:
    BLANK_LINE = 0
    NEW_STATUS = 1
    DELETE_STATUS = 2
    SCRUB_GEO = 3
    LIMIT = 4
    DISCONNECT = 5
    EVENT = 6
    TWEET = 7


def message_type(msg):
    if msg == '':
        return MessageTypes.BLANK_LINE
    elif 'text' in msg:  # HACK!!!
        return MessageTypes.TWEET
    elif 'delete' in msg:
        return MessageTypes.DELETE_STATUS
    elif 'scrub_geo' in msg:
        return MessageTypes.SCRUB_GEO
    elif 'limit' in msg:
        return MessageTypes.LIMIT
    elif 'disconnect' in msg:
        return MessageTypes.DISCONNECT
    elif 'event' in msg:
        return MessageTypes.EVENT


class API:
    '''
    The API is based on generators to play nicely with Twitter's cursor-based
    retrieval. Those generators are (or should be!) transparent for the user.
    The user can always iterate through the generators receiving individual
    responses, and new requests will be sent to Twitter's REST API when
    required. The streaming method also returns generators. This makes it very
    easy to use FRP libraries (e.g. Rx) to work on the resulting streams:

    import logging
    import rx
    from twitter_api import API

    api = API()
    api.auth()
    a = api.get_statuses_sample()
    r = rx.Observable.from_iterable(a)
    r.subscribe(lambda x: logging.warning(x))

    Authentication details can be read from a configuration file (by default
    a file ".twitter" on the current folder)
    Example:

    from twitter_api import API
    api = API()
    api.(app_only=True)
    followers = api.get_follower_ids(screen_name="potus")
    # It's a very long list, Obama is a pretty cool guy. Let's get a few
    subset = [followers.next() for i in range(6000)]
    '''
    # TODO Control the time-based request limits
    # TODO Non-block version
    # TODO Make sure that the ".twitter" file is read from the working folder,
    #      not from the library's folder
    # TODO: Centralise management of HTTP error codes
    #       (see https://dev.twitter.com/streaming/overview/connecting for stream
    #       error codes)
    def __init__(self, consumer_key=None, consumer_secret=None,
                 api_version=API_VERSION, config_file=".twitter",
                 use_developer_token=True):

        # Read app keys from the configuration file if required
        if (consumer_key is None) or (consumer_secret is None):
            # Load from disk
            cfg = ConfigParser()
            try:
                cfg.read(config_file)
            except:
                raise ValueError("Can't read configuration file %s" % config_file)
            if not cfg.has_section('keys'):
                raise ValueError("The config file doesn't have a 'keys' section")
            consumer_key = cfg.get('keys', 'consumer_key')
            consumer_secret = cfg.get('keys', 'consumer_secret')

        if use_developer_token is True:
            logging.info('Using developer key')
            self.access_token = cfg.get('keys', 'access_token')
            self.access_token_secret = cfg.get('keys', 'access_token_secret')

        self.use_developer_token = use_developer_token
        self._initialized = False
        self.consumer_secret = consumer_secret
        self.consumer_key = consumer_key
        self._app_only = False
        self.api_version = api_version
        self.base_api_url = "https://api.twitter.com/%s/" % self.api_version
        self.base_streaming_url = "https://stream.twitter.com/%s/" % self.api_version

    # Decorators
    def requires_user_auth(self, fun):
        def inner(*args, **kwargs):
            if self._app_only is True:
                raise AuthenticationLevelError("This API call requires user-level authentication")
            else:
                return fun(*args, **kwargs)
        return inner

    def check_user_auth(self):
        if self._app_only is True:
            raise AuthenticationLevelError("This API call requires user-level authentication")

    # Authentication
    def app_only_auth(self):
        '''
        Application-only authentication

        This type of authentication does not involve any specific user
        and thus can not access any API function that requires context

        Output:
        access_token: The access token string

        References:
        https://dev.twitter.com/oauth/application-only
        '''
        bearer_cred = "%s:%s" % (self.consumer_key, self.consumer_secret)

        # Standard base64 encoding can result in carriage return characters that
        # can't be part of a headers' value. That's why we use the safe version
        enc = base64.urlsafe_b64encode(bearer_cred)
        headers = {"Authorization": "Basic " + enc,
                   "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}

        response = requests.post(OAUTH2_TOKEN_URL, data="grant_type=client_credentials", headers=headers)
        if response.status_code != 200:
            raise Exception("Authentication unsuccesful! Code %i, Reason: %s" % (response.status_code, response.reason))

        data = response.json()
        assert(data['token_type'] == 'bearer')
        self.access_token = data['access_token']
        self._initialized = True
        self._app_only = True

    def auth(self, app_only=False):
        '''
        User-level authorisation
        '''
        if app_only is True:
            self.app_only_auth()
        elif self.use_developer_token is True:
            self._session = OAuth1Session(self.consumer_key, self.consumer_secret, self.access_token, self.access_token_secret)
            self._initialized = True
            self._app_only = False
        else:
            self._user_oauth()

    def _user_oauth(self):
        '''
        3-legged OAuth1 authentication
        '''
        # Step 1 - Obtain a client identification token
        oauth = OAuth1Session(self.consumer_key, client_secret=self.consumer_secret)
        response = oauth.fetch_request_token(REQUEST_TOKEN_URL)
        print response
        # Step 2 - Obtain authorization from the user
        #   The way this works for most APIs is that the user needs to be
        #   redirected to an URL where he can authorise the access. Once
        #   that is done, the authentication endpoint will redirect the
        #   user to a URL that we specify as a callback, and a verifier
        #   token will be passed as a parameter

        # Step 3 - Obtain an access token
        raise NotImplementedError()
        self._initialized = True
        self._app_only = False

    def _get_requester(self):
        if self._initialized is False:
            raise Exception("Need to authenticate first")
        # Access is granted based on the Authorization field
        # in the HTTPS header
        if self._app_only is True:
            s = requests.Session()
            headers = {"Authorization": "Bearer " + self.access_token}
            s.headers.update(headers)
            logging.info('Using app-level session')
            return s
        else:
            logging.info('Using OAuth1 user session')
            return self._session
        return headers

    def simple_call(self, url, data={}):
        requester = self._get_requester()
        full_url = urljoin(self.base_api_url, url)
        response = requester.get(full_url, params=data)
        if response.status_code == 200:
            return response.json()
        else:
            raise FailedAPICall("Request to %s failed with code %i: %s" % (full_url, response.status_code, response.reason))

    def call(self, url, data):
        '''
        Call Twitter's endpoints with the right authorization
        '''
        base_url = self.base_api_url
        request_data = data.copy()
        if not url.startswith("https://"):
            full_url = urljoin(base_url, url)
        else:
            full_url = url
        return self._cursor_iter(full_url, request_data)

    def _cursor_iter(self, full_url, request_data):
        cursor = -1
        while True:
            requester = self._get_requester()
            request_data['cursor'] = cursor
            logging.info("Sending request to %s" % full_url)
            response = requester.get(full_url, params=request_data)
            if response.status_code == 200:
                yield response
                cursor = response.json()['next_cursor']
                if cursor == 0:
                    raise StopIteration
            if response.status_code == 429:  # Too many requests
                # TODO Do something so that we can continue where we left once the request window is over
                logging.warning("Too many requests. The current set of answers might be incomplete")
                raise StopIteration
            elif response.status_code != 200:
                raise FailedAPICall("Request to %s failed with code %i: %s" % (full_url, response.status_code, response.reason))

    def api_call(self, url, data):
        return self.call(url, data, stream=False)

    def stream_call(self, url, data=None, post=False):
        # TODO: Use GZIP compression (https://dev.twitter.com/streaming/overview/processing)
        if not url.startswith("https://"):
            base_url = self.base_streaming_url
            full_url = urljoin(base_url, url)
        else:
            full_url = url
        requester = self._get_requester()
        if post is False:
            response = requester.get(full_url, params=data, stream=True)
        else:
            response = requester.post(full_url, data=data, stream=True)
        if response.status_code == 200:
            return response.iter_lines()
        elif response.status_code == 420:
            logging.warning("Rate Limited: The client has connected too frequently")
            raise StopIteration
        elif response.status_code != 200:
            raise FailedAPICall("Request to %s failed with code %i: %s" % (full_url, response.status_code, response.reason))

    def get_user_stream(self, track=None, skip_preamble=True, include_followings=True):
        """
        Get a stream of messages for the authenticated user.

        A user stream contains a preamble which is a single message with an array of
        the user id's of the user's friends. The structure of such a message is simply

        {"friends":[id0,...]}

        Inputs:
        - track [None]: Include additional tweets matching any of the keywords in this list
        - skip_preamble [True]: Whether to skip the preamble (list of friend id's)
        - include_followings [True]: Whether to also return messages from accounts that the user follows
        """
        self.check_user_auth()
        endpoint = "https://userstream.twitter.com/%s/user.json" % self.api_version
        params = {}
        if track is not None:
            params.update({"track": ",".join(track)})
        if include_followings is False:
            params.update({"with": "user"})
        stream = self.stream_call(endpoint, params)
        # The user stream has a preamble consisting of a list of the user's friends
        if skip_preamble is True:
            stream.next()
            out = stream
        else:
            out = stream
        return out

    def get_rate_limit_status(self):
        response = self.simple_call("application/rate_limit_status.json")
        return response

    # @requires_user_auth
    def get_statuses_sample(self, track=None, locations=None, follow=None, only_new_status=True):
        """
        Return a stream with a sample of tweets, potentially satisfying some conditions

        Inputs:
            - track [None]: Only get tweets which contain at least one of the keywords in this list
            - follow [None]: Only include tweets from users in this list
            - only_new_status [True]: Filter out all non-new-status (e.g. deletions) messages
        """
        # TODO: Handle locations
        # TODO: Remove non-statuses (e.g. deletions) from the stream
        self.check_user_auth()
        endpoint_sample = "https://stream.twitter.com/%s/statuses/sample.json" % self.api_version
        endpoint_filter = "https://stream.twitter.com/%s/statuses/filter.json" % self.api_version
        params = {}
        if follow is not None:
            params.update({"follow": ",".join(follow)})
        if track is not None:
            params.update({"track": ",".join(track)})
        if follow or track:
            logging.info("Using POST request")
            stream = self.stream_call(endpoint_filter, data=params, post=True)
        else:
            logging.info("Using GET request")
            stream = self.stream_call(endpoint_sample)
        stream = (json.loads(status) for status in stream if status != "")
        if only_new_status is True:
            stream = (st for st in stream if message_type(st) is MessageTypes.TWEET)
        return stream

    def _user_api_call(self, endpoint, screen_name=None, user_id=None):
        if (screen_name is None) and (user_id is None):
            raise ValueError("Either screen_name or user_id must be set")
        if user_id is not None:
            data = {"user_id": user_id}
        else:
            data = {"screen_name": screen_name}
        response = self.call(endpoint, data)
        return response

    def get_friend_ids(self, **kwargs):
        '''
        Get a list of user_id's that a given user is
        following. The user can be specified using
        either screen_name or user_id
        '''
        endpoint = "friends/ids.json"
        response = self._user_api_call(endpoint, **kwargs)
        return flatten(r.json()['ids'] for r in response)

    def get_follower_ids(self, **kwargs):
        '''
        Retrieve the list of user_ids for the followers
        of a user specified by either screen_name or user_id
        '''
        endpoint = "followers/ids.json"
        response = self._user_api_call(endpoint, **kwargs)
        return flatten(r.json()['ids'] for r in response)

    def get_follower_info(self, **kwargs):
        '''
        Retrieve the info for the followers of a user
        specified by either screen_name or user_id
        '''
        endpoint = "followers/list.json"
        response = self._user_api_call(endpoint, **kwargs)
        return flatten(r.json()['users'] for r in response)

    def get_user_info(self, screen_name=None, user_id=None):
        '''
        Retrieve the information for a user / list of users
        specified by either screen_name or user_id
        '''
        endpoint = "users/lookup.json"
        if (screen_name is None) and (user_id is None):
            raise ValueError("Either screen_name or user_id must be set")
        if user_id is not None:
            if not isinstance(user_id, list):
                user_id = [user_id]
            data = {"user_id": ','.join(map(str, user_id))}
        else:
            if not isinstance(screen_name, list):
                screen_name = [screen_name]
            data = {"screen_name": ','.join(map(str, screen_name))}
        response = self.call(endpoint, data)
        return [User(d) for d in response.json()]

    def get_home_timeline(self):
        raise NotImplementedError()
