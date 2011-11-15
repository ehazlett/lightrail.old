import unittest
import logging
import tempfile
import os
import shutil
from random import Random
import string
from subprocess import call, Popen, PIPE
import tarfile
import application
import settings
import utils
import schema
from utils import deploy
try:
    import simplejson as json
except ImportError:
    import json

def get_random_string():
    return ''.join(Random().sample(string.letters+string.digits, 16))

class CoreTestCase(unittest.TestCase):
    def setUp(self):
        self.client = application.app.test_client()

    def test_index(self):
        resp = self.client.get('/')
        assert(resp.status_code == 200 or resp.status_code == 302)

    def test_user_ops(self):
        test_user = get_random_string()
        test_role = get_random_string()
        # create
        assert utils.create_user(username=test_user, password='na', role=test_role)
        assert utils.get_user(test_user) != None
        # toggle
        assert utils.toggle_user(test_user, False)
        user_data = json.loads(utils.get_user(test_user))
        assert user_data['enabled'] == False
        assert utils.toggle_user(test_user, True)
        user_data = json.loads(utils.get_user(test_user))
        assert user_data['enabled'] == True
        assert utils.toggle_user(test_user)
        user_data = json.loads(utils.get_user(test_user))
        assert user_data['enabled'] == False
        # delete
        assert utils.delete_user(test_user)
        assert utils.get_user(test_user) == None
        assert utils.delete_role(test_role)
    
    def test_role_ops(self):
        test_role = get_random_string()
        assert utils.create_role(test_role)
        assert utils.get_role(test_role) != None
        assert utils.delete_role(test_role)
        assert utils.get_role(test_role) == None

    def tearDown(self):
        pass

if __name__=="__main__":
    unittest.main()
