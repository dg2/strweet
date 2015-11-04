'''
Demo application using the Twitter API

Dario Garcia, 2015
'''
import twitter_api as tw
import sys
import signal


def init():
    api = tw.API()
    api.auth()
    return api


def clean_string(string):
    return ' '.join(string.encode("utf-8").splitlines()).replace('|', ' ')


class TooLongBetweenTweets(Exception):
    pass


def timeout_handler(signum, frame):
    raise TooLongBetweenTweets


def process_stream(stream, h, max_elements=None, max_lapse=30):
    counter = 0
    signal.signal(signal.SIGALRM, timeout_handler)
    for status in stream:
        # Use only english tweets
        if status.user.language != 'en':
            continue
        # geo = status.geolocation()
        counter = counter + 1
        line = "%d|%s|%s\n" % (status.timestamp, clean_string(status.user.location),
                               clean_string(status.text))
        h.write(line)
        if counter % 10 == 0:
            sys.stdout.write('.')
            sys.stdout.flush()
        signal.alarm(max_lapse)

if __name__ == '__main__':
    # Parse arguments
    keywords = ['greece']
    filename = 'greece_tweets'
    # bufsize = 1024 * 50  # 50KB
    bufsize = -1  # Use OS default
    max_lapse = 60  # Reset the connection if we don't receive any update in 60s

    # Initialise API
    api = init()
    counter = 0
    with open(filename, mode='a', buffering=bufsize) as h:
        while True:
            # Get a stream
            stream = api.get_statuses_sample(track=keywords)
            try:
                process_stream(stream, h, max_lapse)
            except TooLongBetweenTweets:
                print "Too long between tweets, resetting stream"
                h.write('\n')
                continue
            # TODO: Get hourly topics


# Read back the data:
# >>> pd.read_csv('greece_tweets', header=None, error_bad_lines=False, sep='|')
