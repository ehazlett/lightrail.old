#!/usr/bin/env python
import os
from queue import task
import utils
from utils import config
import schema
import time
import requests
from flask import g, session, current_app, json
import settings

@task
def deploy_package(app_name=None, package=None):
    if not app_name or not package:
        raise NameError('You must specify an app_name and package')
    log = config.get_logger('deploy_package')
    # if app is deployed send message to nodes
    deployed_nodes = utils.get_app_nodes(app_name)
    if deployed_nodes:
        log.debug('{0}: using node(s): {1} for deployment'.format(app_name, \
            deployed_nodes))
    else:
        log.debug('{0}: not found on any existing nodes.'.format(app_name))
        node = utils.get_next_node()
        log.debug('{0}: using node {1} for deployment'.format(app_name, \
            node['node']))
        deployed_nodes = [node]
    ret = {}
    for node in deployed_nodes:
        log.debug('{0}: deploying to {1}'.format(app_name, node['node']))
        headers = {'X-APIKEY': settings.NODE_API_KEY}
        url = 'http://{0}:{1}/api/manage/deploy'.format(node['address'], node['port'])
        log.debug(url)
        resp = requests.post(url, headers=headers, \
            data={'application': app_name}, files={'package': open(package)})
        log.debug('Response: {0}'.format(resp))
        try:
            task = json.loads(resp.content)
        except Exception, e:
            log.error('Unable to parse task: {0}'.format(e))
            task = None
        log.debug(task)
        if task:
            while True:
                task_url = 'http://{0}:{1}/api/task/{2}'.format(node['address'], node['port'], task['task_id'])
                r = requests.get(task_url, headers=headers)
                try:
                    task_status = json.loads(r.content)
                    st = task_status['status'].lower()
                    if st == 'pending' or st == 'running':
                        time.sleep(5)
                    else:
                        ret[node['node']] = task_status['result']
                        break
                except Exception, e:
                    log.error('Unable to parse task: {0}'.format(e))
                    break
    if os.path.exists(package):
        os.remove(package)
    return ret

