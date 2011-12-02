#!/usr/bin/env python
from application import get_db_connection
import settings

def client_listener():
    db = get_db_connection()
    ps = db.pubsub()
    ps.subscribe(settings.CLIENT_CHANNEL)
    for m in ps.listen():
        print(m)

if __name__=='__main__':
    print('MQ up...')
    client_listener()
