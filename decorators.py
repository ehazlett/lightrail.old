#!/usr/bin/env python
from functools import wraps
from flask import g, session, redirect, url_for, request, current_app
from flask import flash
from flask import json
from flask import jsonify
import application
import schema
import messages
import utils

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user' not in session or 'auth_token' not in session:
            flash(messages.ACCESS_DENIED, 'error')
            return redirect(url_for('index'))
        user_key = schema.USER_KEY.format(session['user'])
        user = g.db.get(user_key)
        user_data = json.loads(user)
        if 'role' not in user_data or user_data['role'].lower() != 'admin':
            flash(messages.ACCESS_DENIED, 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'auth_token' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated

def owner_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'app_uuid' in kwargs:
            user = utils.get_user(session['user'])
            app = utils.get_application_config(app_uuid=kwargs['app_uuid'])
            if app['owner'] != user['username']:
                flash(messages.ACCESS_DENIED, 'error')
                return redirect(url_for('applications'))
        return f(*args, **kwargs)
    return decorated

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = None
        if 'apikey' in request.form:
            api_key = request.form['apikey']
        elif 'X-Apikey' in request.headers.keys():
            api_key = request.headers['X-Apikey']
        # validate
        if not api_key:
            data = {'error': messages.NO_API_KEY}
            return jsonify(data)
        if api_key not in utils.get_api_keys():
            data = {'error': messages.INVALID_API_KEY}
            return jsonify(data)
        session['apikey'] = api_key
        return f(*args, **kwargs)
    return decorated

