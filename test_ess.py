import unittest
import json
import time
import ess

api_version='r4'

class TestESS(unittest.TestCase):
    project_id=0
    tjob_id=0
    secjob_id=0
    tjob_exec_inst=0
    def setUp(self):
        with ess.app.app_context():
            self.assertEqual(ess.get_password('miguel'),'python')
            self.assertEqual(ess.get_password('avinash'),None)

    def test_get_password(self):
        with ess.app.app_context():
            self.assertEqual(ess.get_password('miguel'),'python')
            self.assertEqual(ess.get_password('avinash'),None)

    def test_get_scripts_gui(self):
        with ess.app.app_context():
            rv = self.app.get('/gui/scripts.js')
            self.assertTrue("ElasTest ESS GUI JavaScript File" in rv.data)
    
    def test_get_scripts(self):
        with ess.app.app_context():
            rv = self.app.get('/scripts.js')
            self.assertTrue("ElasTest ESS GUI JavaScript File" in rv.data)

    def test_get_webgui(self):
        with ess.app.app_context():
            rv = self.app.get('/gui/')
            self.assertTrue("ElasTest Security Service" in rv.data)

    def test_load_gui(self):
        with ess.app.app_context():
            rv = self.app.get('/')
            self.assertTrue("ElasTest Security Service" in rv.data)

    def test_get_health(self):
        with ess.app.app_context():
            rv = self.app.get('/health/')
            self.assertTrue("ZAP is Ready" in rv.data)

    def test_isZapReady(self):
        with ess.app.app_context():
            self.assertEqual(ess.isZapReady(),'Ready')
            #self.assertTrue("ZAP is Ready" in rv.data)
    """
    def test_create_dummy_project(self):
        with ess.app.app_context():
            rv = self.app.get('/test/project/')
            project=json.loads(json.loads(rv.data))
            TestESS.project_id=project["id"]
            self.assertEqual(project["name"],"UnitTest TJob Project")

    def test_create_dummy_tjob(self):
        with ess.app.app_context():
            rv = self.app.get("/test/tjb/"+str(TestESS.project_id)+"/")
            TestESS.tjob_id=json.loads(json.loads(rv.data))["id"]
            self.assertEqual(json.loads(json.loads(rv.data))["name"],"ESS UnitTest TJob")

    def test_make_public_secjob(self):
        with ess.app.app_context():
            self.assertEqual(ess.make_public_secjob({"id":0,"name":"unittest secjob","vulns":[],"tJobId":TestESS.tjob_id,"maxRunTimeInMins":10}),{"id":0,"name":"unittest secjob","vulns":[],"tJobId":TestESS.tjob_id,"maxRunTimeInMins":10})
            #self.assertTrue("ZAP is Ready" in rv.data)


    def test_create_secjob(self):
        api_version='r3'
        with ess.app.app_context():
            rv = self.app.post('/ess/api/'+api_version+'/secjobs/',data=json.dumps({"id":0,"name":"unittest secjob","vulns":[],"tJobId":TestESS.tjob_id,"maxRunTimeInMins":10}),content_type='application/json')
            TestESS.secjob_id=json.loads(rv.data)["secjob"]["id"]
            self.assertTrue("unittest secjob" in rv.data)

    def test_update_secjob(self):
        api_version='r3'
        with ess.app.app_context():
            rv = self.app.put("/ess/api/"+api_version+"/secjobs/"+str(TestESS.secjob_id)+"/",data=json.dumps({"id":int(TestESS.secjob_id),"name":"Unittest secjob","vulns":[],"tJobId":TestESS.tjob_id,"maxRunTimeInMins":10}),content_type='application/json')
            self.assertTrue("Unittest secjob" in rv.data)

    def test_get_secjobs(self):
        api_version='r3'
        with ess.app.app_context():
            rv = self.app.get('/ess/api/'+api_version+'/secjobs/')
            self.assertTrue("unittest secjob" in rv.data)

    def test_get_secjob(self):
        with ess.app.app_context():
            rv = self.app.get("/ess/api/"+api_version+"/secjobs/"+str(TestESS.secjob_id)+"/")
            self.assertTrue("unittest secjob" in rv.data)

    def test_execute_tjob(self):
        with ess.app.app_context():
            rv = self.app.get('/ess/api/'+api_version+'/tjobs/'+str(TestESS.tjob_id)+'/exec/')
            TestESS.tjob_exec_inst=json.loads(rv.data)["instance"]
            self.assertTrue("IN PROGRESS" in rv.data)

    def test_get_tjob_exec_inst(self):
        with ess.app.app_context():
            rv = self.app.get('/ess/api/'+api_version+'/tjobs/'+str(TestESS.tjob_id)+'/exec/'+str(TestESS.tjob_exec_inst)+'/')
            while "IN PROGRESS" in rv.data or "EXECUTING TEST" in rv.data or "WAITING" in rv.data:
                time.sleep(5)
                rv = self.app.get('/ess/api/'+api_version+'/tjobs/'+str(TestESS.tjob_id)+'/exec/'+str(TestESS.tjob_exec_inst)+'/')
            self.assertTrue("SUCCESS" in rv.data)

    def test_execute_secjob(self):
        with ess.app.app_context():
            rv = self.app.get('/ess/api/'+api_version+'/secjobs/'+str(TestESS.secjob_id)+'/exec/')
            self.assertTrue("inseccookieinfo" in rv.data)

    def test_delete_secjob(self):
        with ess.app.app_context():
            rv = self.app.delete("/ess/api/"+api_version+"/secjobs/"+str(TestESS.secjob_id)+"/")
            self.assertTrue("true" in rv.data)
    """
if __name__=="__main__":
    unittest.main()
