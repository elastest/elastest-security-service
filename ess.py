"""
Author: Avinash Sudhodanan
Project: ElasTest
Description: The following code is the API backend of the ElasTest Security Service
How to run: Download the file and execute "python <filename>" in the commandprompt
Language: Python 2.7 (supposed to work also for python 3 but not properly tested at the moment)
"""
from flask import Flask, jsonify, abort, request, make_response, url_for, render_template
from flask_httpauth import HTTPBasicAuth
import subprocess
import time
from pprint import pprint
from zapv2 import ZAPv2
import os
import requests
import json
from requests.exceptions import ProxyError
import datetime

torm_api="etm:8091" #TORM API URL in production mode
#torm_api="localhost:37000" #TORM API URL in dev mode
tormurl="http://"+torm_api+"/" #TORM API full URL
target = '0.0.0.0' #indicates in which IP address the API listens to
por = 80 #indicates the port
api_version='r4' #represents the current version of the API
zap=ZAPv2() #call to the OWAZP ZAP python API library (https://github.com/zaproxy/zaproxy/wiki/ApiPython)
app = Flask(__name__, static_url_path = "")
auth = HTTPBasicAuth() #for securing api calls using HTTP basic authentication
ess_called=0
ess_finished=0
scans=[] #setting empty secjobs list when api starts
sites_to_be_scanned=[]
time_at_scan = None
time_after_10_min = None

#To be used while implementing HTTPBasicAuth
@auth.get_password
def get_password(username):
    if username == 'miguel':
        return 'python'
    return None

#To be used while implementing HTTPBasicAuth
@auth.error_handler
def unauthorized():
    return make_response(jsonify( { 'error': 'Unauthorized access' } ), 403)
    # return 403 instead of 401 to prevent browsers from displaying the default auth dialog

#To be used while implementing HTTPBasicAuth
@app.errorhandler(400)
def not_found(error):
    return make_response(jsonify( { 'error': 'Bad request' } ), 400)

#To be used while implementing HTTPBasicAuth
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify( { 'error': 'Not found' } ), 404)

#To be used while implementing HTTPBasicAuth
@app.route('/gui/scripts.js', methods = ['GET'])
def get_scripts_gui():
    return render_template('scripts.js')

#To be used while implementing HTTPBasicAuth
@app.route('/scripts.js', methods = ['GET'])
def get_scripts():
    return render_template('scripts.js')

#To be used while implementing HTTPBasicAuth
@app.route('/gui/', methods = ['GET'])
def get_webgui():
    return render_template('ess.html')

#To be used while implementing HTTPBasicAuth
@app.route('/', methods = ['GET'])
def load_gui():
    return render_template('ess.html')

#To be used while implementing HTTPBasicAuth
@app.route('/health/', methods = ['GET'])
def get_health():
	try:
		urls=zap.core.urls
		return jsonify( {'status': "up", "context": {"message":"ZAP is Ready"}})
	except ProxyError:
		return jsonify( {'status': "down", "context": {"message":"ZAP is not Ready"}})

#To know whether TJob called ESS
@app.route('/ess/tjob/execstatus/', methods = ['GET'])
def get_tjob_stat():
        global ess_called
        if ess_called!=0:
            return jsonify({'status': "called"})
        else:
            return jsonify({'status': "not-called"})

#To know whether TJob called ESS
@app.route('/ess/api/'+api_version+'/status/', methods = ['GET'])
def get_ess_stat():
        global ess_finished
        current_time = datetime.datetime.now()
        time_10_min_after_ess_scan = time_at_scan +  datetime.timedelta(minutes = 10)
        if ess_finished==1:
            return jsonify({'status': "finished"})
        elif (current_time >= time_10_min_after_ess_scan):
            return jsonify({'status': "scan-timelimit-exceeded"})
        else:
            return jsonify({'status': "not-yet"})

#To be used while implementing HTTPBasicAuth
@app.route('/ess/scan/start/', methods = ['POST'])
def start_scan():
    if "site" in request.json.keys() and request.json['site']!="":
            print(request.json['site'])
            zap.ascan.scan(request.json['site'])
            return jsonify({'status': "Started Active Scanning"})
    else:
            return jsonify({'status': "ZAP Exception"})


#Function containing all cookie security logic
def get_cookie_sec_report():
    #Logic for detecting non-HTTPS URLs
    all_tjob_urls=list(set(zap.core.urls()))
    insecure_urls=[]
    insecure_cookies=[]
    for url in all_tjob_urls:
    	if not url.startswith("https"):
    		insecure_urls.append(url)
    #Logic for detecting insecure Cookies
    all_tjob_messages=zap.core.messages()
    urls=[]
    results=[]
    resulthttponly={"url":"","method":"","inseccookies":[]}
    cookies=[]
    insecure_cookies=[]
    inSecureFlag=None
    nonHttpOnlyFlag=None
    nonSameSiteFlag=None
    for message in all_tjob_messages:
    	result={"url":"","method":"","allcookies":[], "insecurecookies":[], "nonhttponlycookies":[], "nonsamesitecookies":[]}
    	if message["requestHeader"].split()[1].startswith("https"):
            result["method"]=message["requestHeader"].split()[0]
            result["url"]=message["requestHeader"].split()[1]
            for field in message["responseHeader"].split("\r\n"):
                if(field.startswith("Set-Cookie")):
                    result["allcookies"].append(field.lstrip("Set-Cookie: ").split(";")[0])
                    inSecureFlag=False
                    nonHttpOnlyFlag=False
                    nonSameSiteFlag=False
                    for attributes in field.lstrip("Set-Cookie: ").split(";"):
                        #Logic for detecting cookies without the secure attribute
                    	if attributes.strip().lower().startswith("secure"):
                    		inSecureFlag=True
                        #Logic for detecting cookies without the http-only attribute
                    	if attributes.strip().lower().startswith("httponly"):
                    		nonHttpOnlyFlag=True
                        #Logic for detecting cookies without the samesite attribute
                    	if attributes.strip().lower().startswith("samesite"):
                    		nonSameSiteFlag=True
                    if inSecureFlag==False:
                    	result["insecurecookies"].append(field.lstrip("Set-Cookie:").strip().split(";")[0])
                    if nonHttpOnlyFlag==False:
                    	result["nonhttponlycookies"].append(field.lstrip("Set-Cookie:").strip().split(";")[0])
                    if nonSameSiteFlag==False:
                    	result["nonsamesitecookies"].append(field.lstrip("Set-Cookie:").strip().split(";")[0])
    	if len(result["insecurecookies"])!=0 or len(result["nonhttponlycookies"])!=0 or len(result["nonsamesitecookies"])!=0:
    		results.append(result.copy())
    return {"insecurls":insecure_urls,"inseccookieinfo":results}

#Start Sipder Scan with ZAP
@app.route('/ess/api/'+api_version+'/start/', methods = ['POST'])
def call_ess():
    global ess_called
    global sites_to_be_scanned
    #Start measuring time to avoid ESS run forever
    global time_at_scan
    time_at_scan = datetime.datetime.now()

    ess_called=1
    if "sites" in request.json.keys() and request.json['sites']!=[]:
            sites_to_be_scanned=request.json['sites']
            return jsonify( { 'status': "starting-ess" } )
    else:
            return jsonify({'status': "no-sites-found"})


#Start Sipder Scan with ZAP
@app.route('/ess/api/'+api_version+'/stop/', methods = ['GET'])
def stop_ess():
    global ess_finished
    ess_finished=1
    report=zap.core.alerts()
    report_path=os.environ['ET_FILES_PATH']
    dirname = os.path.dirname(report_path+"report.json")
    if not os.path.exists(dirname):
    	os.makedirs(dirname)
    	print("Had to make directory")
    else:
        with open(report_path+"zap-report.json",'w') as f:
   		       f.write(json.dumps(report))
        print("ZAP Scan Report has been written to the file "+report_path+"zap-report.json")
        with open(report_path+"cookie-report.json",'w') as f:
            f.write(str(get_cookie_sec_report()))
        print("Cookie security report has been written to the file "+report_path+"cookie-report.json")

    return jsonify( { 'status': "stopped-ess" } )


#Start Sipder Scan with ZAP
@app.route('/ess/api/'+api_version+'/getsites/', methods = ['GET'])
def return_sites():
    return jsonify( { 'sites': sites_to_be_scanned } )

#Start Sipder Scan with ZAP
@app.route('/ess/api/'+api_version+'/startspider/', methods = ['POST'])
def start_spider():
    scan_url=str(request.json['url'])
    try:
        zap.urlopen(scan_url)
        time.sleep(2)
        zap.spider.scan(scan_url)
        return jsonify( { 'status': "Started Spidering" } )
    except:
        return jsonify( { 'status': "ZAP Exception" } )

#Start Active Scan with ZAP
@app.route('/ess/api/'+api_version+'/startascan/', methods = ['POST'])
def start_ascan():
    scan_url=str(request.json['url'])
    try:
        time.sleep(5)
        zap.ascan.scan(scan_url)
        return jsonify( { 'status': "Started Active Scanning" } )
    except:
        return jsonify( { 'status': "ZAP Exception" } )

#Check spider scan progress of ZAP
@app.route('/ess/api/'+api_version+'/zap/getstatus/spider/', methods = ['GET'])
def get_status_spider():
    try:
        return jsonify( { 'status': zap.spider.status() } )
    except:
        return jsonify( { 'status': "ZAP Exception" } )

#Check active scan progress of ZAP
@app.route('/ess/api/'+api_version+'/zap/getstatus/ascan/', methods = ['GET'])
def get_status_ascan():
    try:
        return jsonify( { 'status': zap.ascan.status() } )
    except:
        return jsonify( { 'status': "ZAP Exception" } )

#Get Active Scan Report from ZAP
@app.route('/ess/api/'+api_version+'/zap/getscanresults/', methods = ['GET'])
def get_scan_report():
    try:
        alerts=zap.core.alerts()
        high_alerts=[]
        med_alerts=[]
        low_alerts=[]
        sorted_alerts=[]
        for alert in alerts:
            if alert["risk"]=="High":
                high_alerts.append(alert)
            elif alert["risk"]=="Medium":
                med_alerts.append(alert)
            elif alert["risk"]=="Low":
                low_alerts.append(alert)
        if len(high_alerts)!=0:
            sorted_alerts.extend(high_alerts)
        if len(med_alerts)!=0:
            sorted_alerts.extend(med_alerts)
        if len(low_alerts)!=0:
            sorted_alerts.extend(low_alerts)
        return jsonify( { 'status': "Report fetched","report":sorted_alerts} )
    except:
        return jsonify( { 'status': "ZAP Exception" } )

#To check if ZAP has loaded completely by calling its python API
def isZapReady():
	zap=ZAPv2()
	try:
		urls=zap.core.urls
		return "Ready"
	except ProxyError:
		return "NotReady"

if __name__ == '__main__':
	sleeps=[10,10,10,10,10]
	ready=False
	for slp in sleeps:
		if isZapReady()=="Ready":
			ready=True
			break
		else:
			time.sleep(slp)
	if ready==True:
		app.run(host=target, port=por)
