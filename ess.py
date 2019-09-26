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
		urls = zap.core.urls
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

#Function containing all sec report generation logic
def write_report_to_path(report_unsorted, new_path):
    report_unsorted = [{"attack": "", "confidence": "Medium", "wascid": "13", "description": "The cache-control and pragma HTTP header have not been set properly or are missing allowing the browser and proxies to cache content.", "reference": "https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Web_Content_Caching", "sourceid": "3", "solution": "Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate; and that the pragma HTTP header is set with no-cache.", "param": "Cache-Control", "method": "GET", "url": "https://www.gstatic.com/chrome/intelligence/assist/ranker/models/translate/2017/03/translate_ranker_model_20170329.pb.bin", "pluginId": "10015", "other": "", "alert": "Incomplete or No Cache-control and Pragma HTTP Header Set", "messageId": "3", "id": "0", "evidence": "public, max-age=31536000", "cweid": "525", "risk": "Medium", "name": "Incomplete or No Cache-control and Pragma HTTP Header Set"}, {"attack": "", "confidence": "Medium", "wascid": "14", "description": "Web Browser XSS Protection is not enabled, or is disabled by the configuration of the 'X-XSS-Protection' HTTP response header on the web server", "reference": "https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet\nhttps://blog.veracode.com/2014/03/guidelines-for-setting-security-headers/", "sourceid": "3", "solution": "Ensure that the web browser's XSS filter is enabled, by setting the X-XSS-Protection HTTP response header to '1'.", "param": "X-XSS-Protection", "method": "GET", "url": "https://www.gstatic.com/chrome/intelligence/assist/ranker/models/translate/2017/03/translate_ranker_model_20170329.pb.bin", "pluginId": "10016", "other": "The X-XSS-Protection HTTP response header allows the web server to enable or disable the web browser's XSS protection mechanism. The following values would attempt to enable it: \nX-XSS-Protection: 1; mode=block\nX-XSS-Protection: 1; report=http://www.example.com/xss\nThe following values would disable it:\nX-XSS-Protection: 0\nThe X-XSS-Protection HTTP response header is currently supported on Internet Explorer, Chrome and Safari (WebKit).\nNote that this alert is only raised if the response body could potentially contain an XSS payload (with a text-based content type, with a non-zero length).", "alert": "Web Browser XSS Protection Not Enabled", "messageId": "3", "id": "1", "evidence": "X-XSS-Protection: 0", "cweid": "933", "risk": "High", "name": "Web Browser XSS Protection Not Enabled"}, {"attack": "", "confidence": "Medium", "wascid": "15", "description": "X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.", "reference": "http://blogs.msdn.com/b/ieinternals/archive/2010/03/30/combating-clickjacking-with-x-frame-options.aspx", "sourceid": "3", "solution": "Most modern Web browsers support the X-Frame-Options HTTP header. Ensure it's set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. ALLOW-FROM allows specific websites to frame the web page in supported web browsers).", "param": "X-Frame-Options", "method": "GET", "url": "https://www.gstatic.com/chrome/intelligence/assist/ranker/models/translate/2017/03/translate_ranker_model_20170329.pb.bin", "pluginId": "10020", "other": "", "alert": "X-Frame-Options Header Not Set", "messageId": "3", "id": "2", "evidence": "", "cweid": "16", "risk": "Medium", "name": "X-Frame-Options Header Not Set"}, {"attack": "", "confidence": "Medium", "wascid": "13", "description": "The cache-control and pragma HTTP header have not been set properly or are missing allowing the browser and proxies to cache content.", "reference": "https://www.owasp.org/index.php/Session_Management_Cheat_Sheet#Web_Content_Caching", "sourceid": "3", "solution": "Whenever possible ensure the cache-control HTTP header is set with no-cache, no-store, must-revalidate; and that the pragma HTTP header is set with no-cache.", "param": "Cache-Control", "method": "GET", "url": "https://www.example.org/", "pluginId": "10015", "other": "", "alert": "Incomplete or No Cache-control and Pragma HTTP Header Set", "messageId": "13", "id": "3", "evidence": "max-age=604800", "cweid": "525", "risk": "Low", "name": "Incomplete or No Cache-control and Pragma HTTP Header Set"}, {"attack": "", "confidence": "Medium", "wascid": "14", "description": "Web Browser XSS Protection is not enabled, or is disabled by the configuration of the 'X-XSS-Protection' HTTP response header on the web server", "reference": "https://www.owasp.org/index.php/XSS_(Cross_Site_Scripting)_Prevention_Cheat_Sheet\nhttps://blog.veracode.com/2014/03/guidelines-for-setting-security-headers/", "sourceid": "3", "solution": "Ensure that the web browser's XSS filter is enabled, by setting the X-XSS-Protection HTTP response header to '1'.", "param": "X-XSS-Protection", "method": "GET", "url": "https://www.example.org/", "pluginId": "10016", "other": "The X-XSS-Protection HTTP response header allows the web server to enable or disable the web browser's XSS protection mechanism. The following values would attempt to enable it: \nX-XSS-Protection: 1; mode=block\nX-XSS-Protection: 1; report=http://www.example.com/xss\nThe following values would disable it:\nX-XSS-Protection: 0\nThe X-XSS-Protection HTTP response header is currently supported on Internet Explorer, Chrome and Safari (WebKit).\nNote that this alert is only raised if the response body could potentially contain an XSS payload (with a text-based content type, with a non-zero length).", "alert": "Web Browser XSS Protection Not Enabled", "messageId": "13", "id": "4", "evidence": "", "cweid": "933", "risk": "Low", "name": "Web Browser XSS Protection Not Enabled"}, {"attack": "", "confidence": "Medium", "wascid": "15", "description": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.", "reference": "http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx\nhttps://www.owasp.org/index.php/List_of_useful_HTTP_headers", "sourceid": "3", "solution": "Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages.\nIf possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.", "param": "X-Content-Type-Options", "method": "GET", "url": "https://www.example.org/", "pluginId": "10021", "other": "This issue still applies to error type pages (401, 403, 500, etc) as those pages are often still affected by injection issues, in which case there is still concern for browsers sniffing pages away from their actual content type.\nAt \"High\" threshold this scanner will not alert on client or server error responses.", "alert": "X-Content-Type-Options Header Missing", "messageId": "13", "id": "5", "evidence": "", "cweid": "16", "risk": "Low", "name": "X-Content-Type-Options Header Missing"}, {"attack": "", "confidence": "Medium", "wascid": "15", "description": "X-Frame-Options header is not included in the HTTP response to protect against 'ClickJacking' attacks.", "reference": "http://blogs.msdn.com/b/ieinternals/archive/2010/03/30/combating-clickjacking-with-x-frame-options.aspx", "sourceid": "3", "solution": "Most modern Web browsers support the X-Frame-Options HTTP header. Ensure it's set on all web pages returned by your site (if you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. ALLOW-FROM allows specific websites to frame the web page in supported web browsers).", "param": "X-Frame-Options", "method": "GET", "url": "https://www.example.org/", "pluginId": "10020", "other": "", "alert": "X-Frame-Options Header Not Set", "messageId": "13", "id": "6", "evidence": "", "cweid": "16", "risk": "Medium", "name": "X-Frame-Options Header Not Set"}]
    report = []
    for entry in report_unsorted:
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
                if len(str(alert[key])) != 0:
                    each_alert_entry += "<p>" + "<b>" + str(key) + ": " + "</b>" + str(alert[key]) + "</p></br>"
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
        reports += site_name_begin + alerts_begin + collapsible_begin + each_alert + collapsible_end + alerts_end + site_name_end
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
