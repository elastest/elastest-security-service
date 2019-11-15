import unittest
import json
import time
import ess

class TestFlaskApi(unittest.TestCase):
    api_version = 'r4'
    def setUp(self):
        self.app = ess.app.test_client()
        self.app.testing = True

    def test_get_scripts(self):
        response = self.app.get('/gui/scripts.js')
        data = response.get_data()
        self.assertEqual(response.status_code, 200)

    def test_load_gui(self):
        response = self.app.get('/')
        data = response.get_data()
        self.assertTrue("ElasTest Security Service" in data)

    def test_get_webgui(self):
        response = self.app.get('/gui/')
        data = response.get_data()
        self.assertTrue("ElasTest Security Service" in data)

    def test_get_health(self):
        response = self.app.get('/health/')
        data = response.get_data()
        self.assertTrue("ZAP is Ready" in data)

    def test_get_tjob_stat(self):
        response = self.app.get('/ess/tjob/execstatus/')
        data = response.get_data()
        self.assertTrue("called" in data)
    """
    def test_get_ess_stat(self):
        response = self.app.get('/ess/api/'+self.api_version+'/status/')
        data = response.get_data()
        print(data)
        self.assertTrue("not-yet" in data)
    """
if __name__ == "__main__":
    unittest.main()
