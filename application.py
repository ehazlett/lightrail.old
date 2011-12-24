from flask import Flask
from flask import jsonify
from flask import json
from flask import request, Response
from flask import session
from flask import g
from flask import render_template
from flask import redirect, url_for
from flask import flash
from flaskext.babel import Babel
from flaskext.babel import format_datetime
import os
import uuid
import logging
import shutil
import sys
import settings
from optparse import OptionParser
from subprocess import call, Popen, PIPE
from getpass import getpass
import tempfile
from datetime import datetime
from random import Random
import string
import redis
from multiprocessing import Process
import utils
from utils import api
from utils import config
from utils.log import RedisHandler
import queue
import schema
import messages
from decorators import admin_required, login_required, api_key_required

app = Flask(__name__)
app.debug = settings.DEBUG
app.logger.setLevel(logging.ERROR)
app.config.from_object('settings')
# extensions
babel = Babel(app)

# redis handler
redis_handler = RedisHandler()
redis_handler.setLevel(logging.DEBUG)
app.logger.addHandler(redis_handler)

api_log = config.get_logger('api')
console_log = config.get_logger('console')
startup_log = config.get_logger('boot')
log = config.get_logger('webui')

# ----- filters -----
@app.template_filter('date_from_timestamp')
def date_from_timestamp(timestamp):
    return format_datetime(datetime.fromtimestamp(timestamp))

@app.template_filter('date_ms_from_timestamp')
def date_ms_from_timestamp(timestamp):
    return datetime.fromtimestamp(timestamp).strftime('%b %d, %Y %H:%M:%S.%f')

# ----- end filters ----

@app.before_request
def before_request():
    g.db = get_db_connection()

@app.teardown_request
def teardown_request(exception):
    pass

def get_db_connection():
    return redis.Redis(host=app.config['DB_HOST'], port=app.config['DB_PORT'], \
        db=app.config['DB_NAME'], password=app.config['DB_PASSWORD'])

@babel.localeselector
def get_locale():
    # if a user is logged in, use the locale from the account
    if session.has_key('user'):
        user = json.loads(g.db.get(schema.USER_KEY.format(session['user'])))
        if user.has_key('locale'):
            return user['locale']
    # otherwise try to guess the language from the user accept
    # header the browser sends
    return request.accept_languages.best_match([x[0] for x in app.config['LOCALES']])

@app.route("/")
def index():
    if 'auth_token' in session:
        return render_template("index.html")
    else:
        return redirect(url_for('about'))

@app.route("/applications/")
@login_required
def applications():
    app_keys = g.db.keys(schema.APP_KEY.format('*', session['user']))
    apps = []
    [apps.append(json.loads(g.db.get(x))) for x in app_keys]
    ctx = {
        'applications': apps,
    }
    return render_template("applications.html", **ctx)

@app.route("/applications/create/", methods=['GET', 'POST'])
@login_required
def create_application():
    try:
        form = request.form
        utils.create_application(form['name'], owner=session['user'], \
            description=form['description'])
    except Exception, e:
        flash(e, 'error')
    return redirect(url_for('applications'))

@app.route("/about/")
def about():
    return render_template("about.html")

@app.route("/login/", methods=['GET', 'POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user_key = schema.USER_KEY.format(username)
    user = g.db.get(user_key)
    if not user:
        flash(messages.INVALID_USERNAME_PASSWORD, 'error')
    else:
        user_data = json.loads(user)
        if utils.encrypt_password(password, app.config['SECRET_KEY']) == user_data['password']:
            if not user_data['enabled']:
                flash(messages.USER_ACCOUNT_DISABLED, 'error')
            else:
                auth_token = str(uuid.uuid4())
                user_data['auth_token'] = auth_token
                session['user'] = username
                session['role'] = user_data['role']
                session['auth_token'] = auth_token
                g.db.set(user_key, json.dumps(user_data))
        else:
            flash(messages.INVALID_USERNAME_PASSWORD, 'error')
    return redirect(url_for('index'))

@app.route("/logout/", methods=['GET'])
def logout():
    if 'auth_token' in session:
        session.pop('auth_token')
    if 'role' in session:
        session.pop('role')
    if 'user' in session:
        user_key = schema.USER_KEY.format(session['user'])
        user = g.db.get(user_key)
        user_data = json.loads(user)
        user_data['auth_token'] = None
        g.db.set(user_key, json.dumps(user_data))
        session.pop('user')
        flash(messages.LOGGED_OUT)
    return redirect(url_for('index'))

@app.route("/account/", methods=['GET', 'POST'])
@login_required
def account():
    if 'user' in session:
        user_key = schema.USER_KEY.format(session['user'])
        account = utils.get_user(session['user'])
        if request.method == 'GET':
            ctx = {
                'account': account,
                'locales': app.config['LOCALES'],
            }
            return render_template('account.html', **ctx)
        else:
            for k in request.form:
                account[k] = request.form[k]
            g.db.set(user_key, json.dumps(account))
            flash(messages.ACCOUNT_UPDATED, 'success')
    return redirect(url_for('account'))

@app.route("/accounts/")
@admin_required
def accounts():
    users = [json.loads(g.db.get(x)) for x in g.db.keys(schema.USER_KEY.format('*'))]
    roles = [json.loads(g.db.get(x)) for x in g.db.keys(schema.ROLE_KEY.format('*'))]
    ctx = {
        'users': users,
        'roles': roles,
    }
    return render_template('accounts.html', **ctx)

@app.route("/accounts/adduser/", methods=['POST'])
@admin_required
def add_user():
    form = request.form
    try:
        utils.create_user(username=form['username'], email=form['email'], \
            password=form['password'], role=form['role'], enabled=True)
        flash(messages.USER_CREATED, 'success')
    except Exception, e:
        flash('{0} {1}'.format(messages.NEW_USER_ERROR, e), 'error')
    return redirect(url_for('accounts'))

@app.route("/accounts/toggleuser/<username>/")
@admin_required
def toggle_user(username):
    try:
        utils.toggle_user(username)
    except Exception, e:
        app.logger.error(e)
        flash('{0} {1}'.format(messages.ERROR_DISABLING_USER, e), 'error')
    return redirect(url_for('accounts'))

@app.route("/accounts/deleteuser/<username>/")
@admin_required
def delete_user(username):
    try:
        utils.delete_user(username)
        flash(messages.USER_DELETED, 'success')
    except Exception, e:
        flash('{0} {1}'.format(messages.ERROR_DELETING_USER, e), 'error')
    return redirect(url_for('accounts'))

@app.route("/accounts/addrole/", methods=['POST'])
@admin_required
def add_role():
    form = request.form
    try:
        utils.create_role(form['rolename'])
        flash(messages.ROLE_CREATED, 'success')
    except Exception, e:
        flash('{0} {1}'.format(messages.NEW_ROLE_ERROR, e), 'error')
    return redirect(url_for('accounts'))

@app.route("/users/deleterole/<rolename>/")
@admin_required
def delete_role(rolename):
    try:
        utils.delete_role(rolename)
        flash(messages.ROLE_DELETED, 'success')
    except Exception, e:
        flash('{0} {1}'.format(messages.ERROR_DELETING_ROLE, e), 'error')
    return redirect(url_for('accounts'))

@app.route("/tasks/")
@admin_required
def tasks():
    tasks = []
    for t in g.db.keys(schema.TASK_KEY.format('*')):
        tasks.append(json.loads(g.db.get(t)))
    ctx = {
        'tasks': tasks,
    }
    return render_template("tasks.html", **ctx)

@app.route("/tasks/delete/<task_id>/")
@admin_required
def delete_task(task_id):
    # delete 'complete' key
    if task_id.find(':') > -1:
        g.db.delete(task_id)
    else: # task is 'new'
        task_id = int(task_id)
        if task_id == 0:
            g.db.lpop(app.config['TASK_QUEUE_NAME'])
        else: # hack -- rebuild list because `del lindex list <index>` doesn't work in redis-py
            pre = g.db.lrange(app.config['TASK_QUEUE_NAME'], 0, task_id-1)
            post = g.db.lrange(app.config['TASK_QUEUE_NAME'], task_id+1, -1)
            pre.reverse()
            post.reverse()
            g.db.delete(app.config['TASK_QUEUE_NAME'])
            [g.db.lpush(app.config['TASK_QUEUE_NAME'], x) for x in post]
            [g.db.lpush(app.config['TASK_QUEUE_NAME'], x) for x in pre]
    flash('Task deleted...')
    return redirect(url_for('tasks'))

@app.route("/tasks/deleteall/")
@admin_required
def delete_all_tasks():
    g.db.delete(app.config['TASK_QUEUE_NAME'])
    for k in g.db.keys('{0}:*'.format(app.config['TASK_QUEUE_NAME'])):
        g.db.delete(k)
    flash('All tasks removed...')
    return redirect(url_for('tasks'))

@app.route("/logs/")
@admin_required
def logs():
    logs = []
    log_key = schema.LOG_KEY.format('*')
    for l in g.db.keys(log_key):
        logs.append(json.loads(g.db.get(l)))
    ctx = {
        'logs': logs,
    }
    return render_template("logs.html", **ctx)

@app.route("/logs/clear/")
@admin_required
def clear_logs():
    for k in g.db.keys(schema.LOG_KEY.format('*')):
        g.db.delete(k)
    flash('Logs cleared...')
    return redirect(url_for('logs'))

@app.route("/nodes/")
@admin_required
def nodes():
    nodes = []
    node_keys = g.db.keys('{0}'.format(schema.HEARTBEAT_KEY.format('*')))
    for k in node_keys:
        data = json.loads(g.db.get(k))
        node = {}
        node['name'] = data['node']
        node['ttl'] = g.db.ttl(k)
        node['load'] = data['load']
        nodes.append(node)
    ctx = {
        'nodes': nodes,
    }
    return render_template("nodes.html", **ctx)

# ----- API -----
@app.route("/api/manage/<app_uuid>/deploy", methods=['POST'])
@api_key_required
def api_app_deploy(app_uuid=None):
    try:
        data = {}
        pkg_id = app_uuid
        # check if owner
        app_config = utils.get_application_config(app_uuid=app_uuid)
        user = utils.get_user(apikey=session['apikey'])
        if app_config['owner'] != user['username']:
            data['error'] = messages.ACCESS_DENIED
            status = 400
        else:
            f = request.files['package']
            pkg_name = os.path.join(app.config['DEPLOY_WORK_DIR'], pkg_id)
            f.save(pkg_name)
            api_log.info('Deploy for {0} requested from {1} ({2})'.format(\
                app_config['name'], user['username'], request.remote_addr))
            data['task_id'] = api.deploy_package.delay(app_config['name'], pkg_name).key
            status = 200
    except Exception, e:
        data = {'error': str(e)}
        status = 400
    return make_api_response(json.dumps(data), status)

@app.route("/api/task/<task_id>/result")
@admin_required
def api_task_result(task_id=None):
    try:
        task = g.db.get(schema.TASK_KEY.format(task_id))
        if task:
            data = {'result': json.loads(json.loads(task.replace('\n', ''))['result'])}
        else:
            data = {'result': messages.INVALID_TASK}
        print(data['result'])
        status = 200
    except Exception, e:
        data = {'error': str(e)}
        status = 400
    return make_api_response(json.dumps(data), status)

@app.route("/api/generateapikey/")
@login_required
def api_generate_apikey():
    data = {
        "key": ''.join(Random().sample(string.letters+string.digits, 32)),
    }
    return jsonify(data)

def make_api_response(data=None, status=200):
    return Response(data, status=status, mimetype='application/json')

# ----- END API -----

# ----- management commands -----
def create_user():
    db = get_db_connection()
    try:
        username = raw_input('Username: ').strip()
        email = raw_input('Email: ').strip()
        while True:
            password = getpass('Password: ')
            password_confirm = getpass(' (confirm): ')
            if password_confirm == password:
                break
            else:
                print('Passwords do not match... Try again...')
        role = raw_input('Role: ').strip()
        # create role if needed
        if not db.get(schema.ROLE_KEY.format(role)):
            utils.create_role(role)
        utils.create_user(username=username, email=email, password=password, \
            role=role, enabled=True)
        print('User created/updated successfully...')
    except KeyboardInterrupt:
        pass

def toggle_user(active):
    try:
        username = raw_input('Enter username: ').strip()
        try:
            utils.toggle_user(username, active)
        except Exception, e:
            print(e)
            sys.exit(1)
    except KeyboardInterrupt:
        pass

def client_listener():
    db = get_db_connection()
    ps = db.pubsub()
    ps.subscribe(settings.CLIENT_CHANNEL)
    for m in ps.listen():
        print(m)

# ----- end management commands -----

if __name__=="__main__":
    op = OptionParser()
    op.add_option('--create-user', dest='create_user', action='store_true', default=False, help='Create/update user')
    op.add_option('--enable-user', dest='enable_user', action='store_true', default=False, help='Enable user')
    op.add_option('--disable-user', dest='disable_user', action='store_true', default=False, help='Disable user')
    op.add_option('--port', dest='port', default='5000', help='Port to run Werkzeug debug server')
    opts, args = op.parse_args()

    if opts.create_user:
        create_user()
        sys.exit(0)
    if opts.enable_user:
        toggle_user(True)
        sys.exit(0)
    if opts.disable_user:
        toggle_user(False)
        sys.exit(0)
    # run app
    app.run(port=int(opts.port))

