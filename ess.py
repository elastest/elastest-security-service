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
from attack_page_getter import COSIAttackFinder

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
states = []
state_req_res_info = []
noisy_url_domains = ["https://tracking-protection.cdn.mozilla.net", "https://www.google.com", "https://fonts.gstatic.com", "https://www.gstatic.com", "https://fonts.googleapis.com"]
url_state_map = {}
url_occurance_count_map = {}
not_visited_url_state_map = {}
all_urls = []
browser = "chrome"
browser_version = "78.0"

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
def bad_req(error):
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
		urls = zap.core.urls()
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
        time_10_min_after_ess_scan = time_at_scan +  datetime.timedelta(minutes = 5)
        if ess_finished==1:
            return jsonify({'status': "finished"})
        elif (current_time >= time_10_min_after_ess_scan):
            return jsonify({'status': "scan-timelimit-exceeded"})
        else:
            return jsonify({'status': "not-yet"})

#To start ZAP active scan
@app.route('/ess/scan/start/', methods = ['POST'])
def start_scan():
    if "site" in request.json.keys() and request.json['site']!="":
            print(request.json['site'])
            zap.ascan.scan(request.json['site'])
            return jsonify({'status': "Started Active Scanning"})
    else:
            return jsonify({'status': "ZAP Exception"})

#Function containing all sec report generation logic
def write_report_to_path(report_unsorted, new_path):
    #report_unsorted = zap.core.alerts()
    report = []
    pprint(type(report_unsorted))
    report_unsorted = json.loads(report_unsorted)
    for entry in report_unsorted:
	print("Entry")
	pprint(entry)
        if entry["risk"] == "High":
            report.append(entry)
    for entry in report_unsorted:
        if entry["risk"] == "Medium":
            report.append(entry)
    for entry in report_unsorted:
        if entry["risk"] == "Low":
            report.append(entry)

    url_key_report = {}
    for entry in report:
        if(entry["url"] not in list(url_key_report.keys())):
            url_key_report[entry["url"]] = [entry]
        else:
            url_key_report[entry["url"]].append(entry)

    part_1 = """
    <!DOCTYPE html>
    <html>
    <head>
    <title>ESS Scan Report</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0-alpha.4/css/materialize.min.css">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
    <script type = "text/javascript" src = "https://code.jquery.com/jquery-2.1.1.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/materialize/1.0.0-alpha.4/js/materialize.min.js"></script>
    </head>

    <body>
    <!-- LEFT LOGO -->
    <nav>
        <div class="nav-wrapper grey darken-1">
            <a href="" class="brand-logo">ElasTest Security Service (ESS)</a>
        </div>
    </nav>
    <div class="container">
    <h5>ESS Security Scan Report</h5>
    <ul class="collapsible">
    """
    reports = ""
    count = 0
    for site in list(url_key_report.keys()):
        site_name_begin = """
            <li>
                <div class="collapsible-header"><i class="material-icons">bug_report</i>"""+site+"</div>"
        each_alert = ""
        for alert in url_key_report[site]:
            if alert["risk"] == "High":
                color = "red-text"
            elif alert["risk"] == "Medium":
                color = "orange-text"
            else:
                color = ""
            count+=1
            alerts_begin = """<div class="collapsible-body">"""
            collapsible_begin = "<ul class=\"collapsible\">"
            each_alert_entry = ""
            for key in list(alert.keys()):
		print(key)
		print(alert[key])
		print(type(key))
		print(type(alert[key]))
                if alert[key] != "":
		    if key != "cosi_attacks":
                    	each_alert_entry += "<p>" + "<b>" + str(key) + ": " + "</b>" + str(alert[key]) + "</p></br>"
		    elif key == "cosi_attacks":
			each_alert_entry += "<p>" + "<b>" + str(key) + ": " + "</b><textarea disabled>" + str(alert[key]) + "</textarea></p></br>"
            each_alert += """
                <li>
                <div class="collapsible-header"><i class="material-icons """+color+"""\">lens</i>Alert """+str(count)+"""</div>
                <div class = "collapsible-body"><span>"""+each_alert_entry+"""</span></div>
                </li>"""
        count = 0
        collapsible_end = "</ul>"
        alerts_end  = "</div>"
        site_name_end =     """
            </li>
        """
        reports += site_name_begin.encode('utf-8') + alerts_begin.encode('utf-8') + collapsible_begin.encode('utf-8') + each_alert.encode('utf-8') + collapsible_end.encode('utf-8') + alerts_end.encode('utf-8') + site_name_end.encode('utf-8')
    end = """
    </ul>
    </div>
    """
    part_2 = """
    <script>
    $(document).ready(function(){
        $('.collapsible').collapsible();
    });

    $(document).click(function(){
        $('.collapsible').collapsible();
    });
    </script>
    </body>
    </html>
    """
    new_days = open(new_path,'w')
    new_days.write(part_1+reports+end+part_2)
    new_days.close()

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
        write_report_to_path(json.dumps(report), report_path+"zap-report.html")
        print("ZAP Scan Report has been written to the file "+report_path+"zap-report.html")
        #with open(report_path+"cookie-report.json",'w') as f:
        #  f.write(str(get_cookie_sec_report()))

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
		urls=zap.core.urls()
		return "Ready"
	except ProxyError:
		return "NotReady"

def is_present_in_diclst(key,value,list):
    for dic in list:
        if key in dic.keys():
            if dic[key] == value:
                return True
    return False

#Function to start state script execution
@app.route('/ess/api/'+api_version+'/startstate/', methods = ['POST'])
def start_state_script():
    global states
    if request.json['statename'] not in states:
        states.append(request.json['statename'])
    zap.core.new_session()
    return jsonify({'status': "State script starting noted"})

#Function to note end of state script execution
@app.route('/ess/api/'+api_version+'/finishstate/', methods = ['POST'])
def finish_state_script():
    global state_req_res_info
    all_tjob_messages = zap.core.messages()
    for message in all_tjob_messages:
        if message["type"] != "0":
        	entry={"url":"", "request_header":"", "response_header":"", "response_body":"", "request_body":"", "state":""}
        	entry["url"] = message["requestHeader"].split()[1]
        	all_urls.append(entry["url"])
        	entry["state"] = request.json['statename']
        	entry["request_header"] = message["requestHeader"]
        	entry["response_header"] = message["responseHeader"]
        	entry["response_body"] = message["responseBody"]
        	if message["requestHeader"].split()[0].startswith("P"):
        	    entry["request_body"] = message["requestBody"]
        	state_req_res_info.append(entry)
    make_url_map()
    return jsonify({'status': "State script finish noted"})

#Function to make a map of URLs and associated states
def make_url_map():
    global url_state_map
    for entry in state_req_res_info:
        if entry["url"] not in list(url_state_map.keys()):
            url_state_map[entry["url"]] = [entry["state"]]
        elif entry["state"] not in url_state_map[entry["url"]]:
            url_state_map[entry["url"]].append(entry["state"])

#Function to make a map of URLs and associated states
def make_not_visited_url_map():
    global not_visited_url_state_map
    for url in list(url_state_map.keys()):
        not_visited_url_state_map[url] = list(set(states) - set(url_state_map[url]))

#Function to note end of state script execution
@app.route('/ess/api/'+api_version+'/startprivacycheck/', methods = ['POST'])
def start_privacy_check():
    make_not_visited_url_map()
    global browser
    global browser_version
    browser = request.json['browser']
    browser_version = request.json['browser_version']
    return jsonify({'status': "Start Privacy Check", "not_visited_url_state_map":not_visited_url_state_map})
#End code for privacy check functionality

def get_header_value(header_to_find, headers_list):
    for header_value in headers_list:
        if header_value.startswith(header_to_find):
            return header_value.lstrip(header_to_find+":")
    return "Not Found"
#Send end privacy check notification
@app.route('/ess/api/'+api_version+'/endprivacycheck/', methods = ['GET'])
def end_privacy_check():
    state_table = {}
    urls_worth_considering = []
    make_url_map()
    cosi_report = []
    for key in list(url_state_map.keys()):
        if len(url_state_map[key]) > 1:
            state_table[key] = []
            for entry in state_req_res_info:
                if entry["url"] == key:
                    state_info = {"state":entry["state"],
                    "response_code":entry["response_header"].split(" ")[1][0:3],
                    "response_headers":entry["response_header"].strip("\r\n\r\n").split("\r\n")[1:],
                    "response_header_x_content_type_options": get_header_value("X-Content-Type-Options", entry["response_header"].strip("\r\n\r\n").split("\r\n")[1:]),
                    "response_header_content_type":get_header_value("Content-Type", entry["response_header"].strip("\r\n\r\n").split("\r\n")[1:]),
                    "response_header_x_frame_options": get_header_value("X-Frame-Options", entry["response_header"].strip("\r\n\r\n").split("\r\n")[1:]),
                    "response_header_content_disposition":get_header_value("Content-Disposition", entry["response_header"].strip("\r\n\r\n").split("\r\n")[1:])
                    }
                    state_table[key].append(state_info)
    atkFinder = COSIAttackFinder()
    #pprint(atkFinder.get_attack_inclusion("200", "enabled", "application/pdf", "disabled", "inline",
    #                                      "302", "enabled", "text/html", "disabled", "disabled",
    #                                      "chrome", "60.0"))
    for key in list(state_table.keys()):
        print("-===URL: "+key+" ===-")
        state_a_res_code = ""
        state_a_cto = ""
        state_a_ctype = ""
        state_a_xfo = ""
        state_a_cd = ""
        state_a_headers = ""

        state_b_res_code = ""
        state_b_cto = ""
        state_b_ctype = ""
        state_b_xfo = ""
        state_b_cd = ""
        state_b_headers = ""
        for entry in state_table[key]:
            if entry["state"] == states[0]:
                state_a_res_code = entry["response_code"].strip()
                state_a_cto = entry["response_header_x_content_type_options"].strip()
                state_a_ctype = entry["response_header_content_type"].strip().split(";")[0]
                state_a_xfo = entry["response_header_x_frame_options"].strip()
                state_a_cd = entry["response_header_content_disposition"].strip().split(";")[0]
                state_a_headers = entry["response_headers"]
            if entry["state"] == states[1]:
                state_b_res_code = entry["response_code"].strip()
                state_b_cto = entry["response_header_x_content_type_options"].strip()
                state_b_ctype = entry["response_header_content_type"].strip().split(";")[0]
                state_b_xfo = entry["response_header_x_frame_options"].strip()
                state_b_cd = entry["response_header_content_disposition"].strip().split(";")[0]
                state_b_headers = entry["response_headers"]

        if state_a_cto == "Not Found":
            state_a_cto = "disabled"
        else:
            state_a_cto = "enabled"

        if state_a_ctype == "Not Found":
            state_a_ctype = ""

        if state_a_xfo == "Not Found":
            state_a_xfo = "disabled"
        else:
            state_a_xfo = "enabled"

        if state_a_cd == "Not Found":
            state_a_cd = ""

        if state_b_cto == "Not Found":
            state_b_cto = "disabled"
        else:
            state_b_cto = "enabled"

        if state_b_ctype == "Not Found":
            state_b_ctype = ""

        if state_b_xfo == "Not Found":
            state_b_xfo = "disabled"
        else:
            state_b_xfo = "enabled"

        if state_b_cd == "Not Found":
            state_b_cd = ""
	
	cosi_report_entry = {}
	cosi_report_entry["url"] = key
	cosi_report_entry["state_a"] = states[0]
	cosi_report_entry["state_b"] = states[1]
        print("-==State A info==-")
        print("state_a_res_code: "+state_a_res_code)
	cosi_report_entry["state_a_res_code"] = state_a_res_code
        print("state_a_cto: "+state_a_cto)
        print("state_a_ctype: "+state_a_ctype)
        print("state_a_xfo: "+state_a_xfo)
        print("state_a_cd: "+state_a_cd)
        print("state_a_headers: "+ str(state_a_headers))
	cosi_report_entry["state_a_headers"] = state_a_headers
        print("-==State B info==-")
        print("state_b_res_code: "+state_b_res_code)
	cosi_report_entry["state_b_res_code"] = state_b_res_code
        print("state_b_cto: "+state_b_cto)
        print("state_b_ctype: "+state_b_ctype)
        print("state_b_xfo: "+state_b_xfo)
        print("state_b_cd: "+state_b_cd)
        print("state_b_headers: "+ str(state_b_headers))
	cosi_report_entry["state_b_headers"] = state_b_headers
        cosi_attacks = atkFinder.get_attack_inclusion(state_a_res_code, state_a_cto, state_a_ctype, state_a_xfo, state_a_cd,
                                 state_b_res_code, state_b_cto, state_b_ctype, state_b_xfo, state_b_cd,
                                 browser, browser_version)
	cosi_report_entry["cosi_attacks"] = cosi_attacks
	cosi_report_entry["risk"] = "Medium"
	if len(cosi_attacks) != 0:
		cosi_report.append(cosi_report_entry)		
        print("---------------------")
        print("")
    pprint(json.dumps(cosi_report))
    #Start report storing
    report_path=os.environ['ET_FILES_PATH']
    print("Report file path is :"+report_path)
    #report_path="/home/wolverine/elastest-security-service/"
    write_report_to_path(json.dumps(cosi_report), report_path+"cosi-report.html")
    print("COSI Scan Report has been written to the file "+report_path+"cosi-report.html")
    #End report storing
    return jsonify(atkFinder.get_attack_inclusion("200", "enabled", "application/pdf", "disabled", "inline",
                                          "302", "enabled", "text/html", "disabled", "disabled",
                                          "chrome", "60.0"))

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
