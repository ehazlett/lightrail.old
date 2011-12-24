import hashlib
from random import Random
import string
import schema
import application
import settings
import uuid
from queue import task
from utils import config
try:
    import simplejson as json
except ImportError:
    import json

VALID_CHARS = string.letters+string.digits+'-'

def create_user(username=None, email=None, password=None, role=None, enabled=True):
    if not username or not password or not role:
        raise NameError('You must specify a username, password, and role')
    db = application.get_db_connection()
    user_key = schema.USER_KEY.format(username)
    data = schema.user(username=username, email=email, \
        password=encrypt_password(password, settings.SECRET_KEY), \
        role=role, enabled=enabled)
    db.set(user_key, json.dumps(data))
    return True

def get_user(username=None, apikey=None):
    if not username and not apikey:
        raise NameError('You must specify a username or apikey')
    db = application.get_db_connection()
    if not username:
        data = [x.split(':')[1] for x in db.keys(schema.USER_KEY.format('*'))\
            if json.loads(db.get(x))['apikey'] == apikey]
        if data:
            username = data[0]
    user_key = schema.USER_KEY.format(username)
    user = db.get(user_key)
    if user:
        data = json.loads(user)
    else:
        data = None
    return data

def get_api_keys():
    db = application.get_db_connection()
    return [json.loads(db.get(x))['apikey'] for x in \
        list(db.keys(schema.USER_KEY.format('*')))]

def delete_user(username=None):
    if not username:
        raise NameError('You must specify a username')
    db = application.get_db_connection()
    user_key = schema.USER_KEY.format(username)
    db.delete(user_key)
    return True

def create_role(rolename=None):
    if not rolename:
        raise NameError('You must specify a rolename')
    db = application.get_db_connection()
    role_key = schema.ROLE_KEY.format(rolename)
    data = schema.role(rolename)
    db.set(role_key, json.dumps(data))
    return True

def get_role(rolename=None):
    if not rolename:
        raise NameError('You must specify a rolename')
    db = application.get_db_connection()
    role_key = schema.ROLE_KEY.format(rolename)
    return db.get(role_key)

def delete_role(rolename=None):
    if not rolename:
        raise NameError('You must specify a rolename')
    db = application.get_db_connection()
    role_key = schema.ROLE_KEY.format(rolename)
    db.delete(role_key)
    return True

def toggle_user(username=None, enabled=None):
    if not username:
        raise NameError('You must specify a username')
    db = application.get_db_connection()
    user_key = schema.USER_KEY.format(username)
    user = db.get(user_key)
    if user:
        user_data = json.loads(user)
        if enabled != None:
            user_data['enabled'] = enabled
        else:
            current_status = user_data['enabled']
            if current_status:
                enabled = False
            else:
                enabled = True
            user_data['enabled'] = enabled
        db.set(user_key, json.dumps(user_data))
        return True
    else:
        raise RuntimeError('User not found')

def encrypt_password(password=None, salt=None):
    h = hashlib.sha256(salt)
    h.update(password+salt)
    return h.hexdigest()

def get_task(task_id=None):
    if not task_id:
       raise NameError('You must specify a task id')
    db = application.get_db_connection()
    task_key = '{0}:{1}'.format(settings.TASK_QUEUE_NAME, task_id)
    return db.get(task_key)

def create_application(name=None, owner=None, **kwargs):
    if not name or not owner:
        raise NameError('You must specify a name and owner')
    # check name for invalid chars
    for c in name:
        if c not in VALID_CHARS:
            raise ValueError('Invalid characters in name')
    db = application.get_db_connection()
    if get_application_config(name):
        raise NameError('An application by that name already exists')
    app_key = schema.APP_KEY.format(name, owner)
    app_data = schema.application(name=name, owner=owner)
    for k,v in kwargs.iteritems():
        app_data[k] = v
    # uuid for app
    app_data['uuid'] = str(uuid.uuid4())
    db.set(app_key, json.dumps(app_data))
    return True

def get_app_name(app_uuid=None):
    if not app_uuid:
        raise NameError('You must specify an app_uuid')
    db = application.get_db_connection()
    app = [x.split(':')[1] for x in db.keys(schema.APP_KEY.format('*', '*')) \
        if json.loads(db.get(x))['uuid'] == app_uuid]
    if app:
        app = app[0]
    else:
        app = None
    return app

def get_application_config(app_name=None, app_uuid=None):
    if not app_name and not app_uuid:
        raise NameError('You must specify an app_name or app_uuid')
    db = application.get_db_connection()
    if not app_name:
        app_name = get_app_name(app_uuid)
    app_key = schema.APP_KEY.format(app_name, '*')
    res = db.keys(app_key)
    if res:
        app = json.loads(db.get(res[0]))
    else:
        app = None
    return app

def update_application_config(app=None, config={}):
    if not application:
        raise NameError('You must specify an application')
    db = application.get_db_connection()
    app_key = schema.APP_KEY.format(app)
    db.set(app_key, json.dumps(config))
    return True

def remove_application_config(app=None):
    if not application:
        raise NameError('You must specify an application')
    db = application.get_db_connection()
    app_key = schema.APP_KEY.format(app)
    db.delete(app_key)
    return True

def get_next_application_port():
    db = application.get_db_connection()
    k = schema.PORTS_KEY
    port = None
    ports = db.get(k)
    if not ports:
        ports = []
    else:
        try:
            ports = json.loads(ports)
        except:
            ports = []
    # generate and make sure port not already used
    while True:
        port = Random().randint(settings.APP_MIN_PORT, settings.APP_MAX_PORT)
        if port not in ports:
            break
    return port

def reserve_application_port(port=None):
    if not port:
        raise NameError('You must specify a port')
    db = application.get_db_connection()
    ports = db.get(schema.PORTS_KEY)
    if not ports:
        ports = []
    else:
        try:
            ports = json.loads(ports)
        except:
            ports = []
    if port in ports:
        raise RuntimeError('Port already reserved')
    ports.append(port)
    db.set(schema.PORTS_KEY, json.dumps(ports))
    return True

def release_application_port(port=None):
    if not port:
        raise NameError('You must specify a port')
    db = application.get_db_connection()
    ports = db.get(schema.PORTS_KEY)
    if ports:
        try:
            ports = json.loads(ports)
            ports.remove(port)
            db.set(schema.PORTS_KEY, json.dumps(ports))
        except:
            pass

def publish_master_message(msg={}):
    if not msg:
        raise NameError('You must specify a message')
    db = application.get_db_connection()
    # check type
    if not isinstance(msg, dict):
        msg = {'data': msg}
    db.publish(settings.MASTER_CHANNEL, json.dumps(msg))
    return True

def get_app_nodes(app_name=None):
    if not app_name:
        raise NameError('You must specify an app_name')
    db = application.get_db_connection()
    # HACK -- fix to not split(':') -- TODO: dynamically lookup node name
    return [get_node(x.split(':')[1]) for x in db.keys(schema.NODE_APPS_KEY.format('*')) \
        if app_name in db.smembers(x)]

def get_node(node_name=None):
    if not node_name:
        raise NameError('You must specify a node_name')
    db = application.get_db_connection()
    node_hb = db.get(schema.HEARTBEAT_KEY.format(node_name))
    if node_hb:
        data = json.loads(node_hb)
    else:
        data = None
    return data

def get_next_node():
    db = application.get_db_connection()
    all_nodes = []
    [all_nodes.append(x.split(':')[1]) for x in db.keys(schema.HEARTBEAT_KEY.format(\
        '*'))]
    if len(all_nodes) == 1:
        node = all_nodes[0]
    elif len(all_nodes) > 1:
        # check for lowest cpu load
        stat = {}
        for n in all_nodes:
            try:
                stats = json.loads(db.get(schema.HEARTBEAT_KEY.format(n)))
                if not stat:
                    stat['node'] = n
                    stat['load'] = stats['load']
                else:
                    # check 15 min load
                    if stats['load'][2] < stat['load'][2]:
                        stat['node'] = n
                        stat['load'] = stats['load']
                        break
            except:
                pass # ignore errors
        node = stat['node']
    else:
        node = None
    if node:
        return json.loads(db.get(schema.HEARTBEAT_KEY.format(node)))
    else:
        return None

