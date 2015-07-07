'''
Demo application using the Twitter API

Dario Garcia, 2015
'''
import twitter_api as tw
import time

interval = 0.3


def init():
    api = tw.API()
    api.auth()
    return api

if __name__ == '__main__':
    # Parse arguments
    keywords = ['greece']
    # Initialise API
    api = init()
    # Get a stream
    stream = api.get_statuses_sample(track=keywords)
    for status in stream:
        print status['text']
        time.sleep(interval)
