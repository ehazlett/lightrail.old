#!/usr/bin/env python
from application import get_db_connection
from utils import config
import settings
try:
    import simplejson as json
except ImportError:
    import json

def client_listener():
    log = config.get_logger('client_listener')
    db = get_db_connection()
    ps = db.pubsub()
    ps.subscribe(settings.CLIENT_CHANNEL)
    for m in ps.listen():
        try:
            print(m)
        except Exception, e:
            log.error('Unable to parse client message: {0}'.format(e))

if __name__=='__main__':
    print('MQ up...')
    client_listener()
