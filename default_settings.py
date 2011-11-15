import os
import logging
import sys
sys.path.append('./')
try:
    import simplejson as json
except ImportError:
    import json

APP_NAME = 'lightrail'
DEBUG = True
# db
DB_HOST = 'localhost'
DB_PORT = 6379
DB_NAME = 0
DB_USER = '<DBUSER>'
DB_PASSWORD = '<DBPASS>'
NODE_NAME = os.uname()[1]
PROJECT_PATH = os.path.dirname(__file__)
SECRET_KEY = "<SECRET_KEY>"
# queue settings
TASK_QUEUE_NAME = 'queue:{0}'.format(APP_NAME)
TASK_QUEUE_KEY_TTL = 86400
# app version
VERSION = '0.1'

try:
    from local_settings import *
except ImportError:
    pass
