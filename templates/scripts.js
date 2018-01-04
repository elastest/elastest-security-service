api_version="r3";
//Function to send API request with the entered tjob id
function addTJobId(){
  return "/ess/api/"+api_version+"/secjobs/"+$("#tjobid").val()+"/exec";
}
//Function to update the progress bar of each test
function changeProgress(element,percentage){
  $(element).attr("style", "width: "+percentage+"%");
}
//Function that appends each insecure URL to the UI
function showReport(result_location){
  url= addTJobId();
  $.get(url, function(responseTxt, statusTxt, xhr){
    if(statusTxt == "success"){
      result_location.parentNode.nextSibling.nextSibling.firstChild.nextSibling.firstChild.innerHTML="HTTP Traffic Analysis Status: "+"<p style=\"color:blue\">"+"COMPLETED"+"</p>"
      result_location.parentNode.nextSibling.nextSibling.firstChild.nextSibling.firstChild.nextSibling.firstChild.setAttribute("style","width: "+100+"%");
      if (responseTxt.insecurls.length==0) {
        $(result_location).parent().siblings("div.collection").children().first().next().next().append("<div id=\"insecureurl\" style=\"color:green\">"+"None found"+"</div>")
      }
      else {
        for ( var i = 0, l = responseTxt.insecurls.length; i < l; i++ ) {
            $(result_location).parent().siblings("div.collection").children().first().next().next().append("<div id=\"insecureurl\" style=\"color:red\">"+responseTxt.insecurls[i]+"</div>")
        }
      }
      //console.log(responseTxt)

      if (responseTxt.inseccookieinfo.length==0) {

        $(result_location).parent().siblings("div.collection").children().first().next().next().next().append("<div id=\"insecureurl\" style=\"color:green\">"+"None found"+"</div>")
        $(result_location).parent().siblings("div.collection").children().first().next().next().next().next().append("<div id=\"insecureurl\" style=\"color:green\">"+"None found"+"</div>")
        $(result_location).parent().siblings("div.collection").children().first().next().next().next().next().next().append("<div id=\"insecureurl\" style=\"color:green\">"+"None found"+"</div>")
      }
      else {

        //Code to add cookies missing secure flag
        var secureFlagTab=false

        for (var i = 0, l = responseTxt.inseccookieinfo.length; i < l; i++) {
            if (responseTxt.inseccookieinfo[i].insecurecookies.length==0) {
              continue
            }
            else {
                  if (secureFlagTab==false){
                  $(result_location).parent().siblings("div.collection").children().first().next().next().next().append("<br><div id=\"inseccookurl\" style=\"color:black\"><table><thead><tr><th>URL</th><th>Method</th><th>Cookie</th></tr></thead><tbody></tbody></table></div>")
                  secureFlagTab=true
                  }

                  //console.log(responseTxt.inseccookieinfo[i].insecurecookies)
                  for (var j = 0, m = responseTxt.inseccookieinfo[i].insecurecookies.length;j<m ;j++) {
                    if (j==0) {
                      $(result_location).parent().siblings("div.collection").children().first().next().next().next().children().first().next().next().children().first().children().first().next().append("<tr><td>"+responseTxt.inseccookieinfo[i].url+"</td><td>"+responseTxt.inseccookieinfo[i].method+"</td><td>"+responseTxt.inseccookieinfo[i].insecurecookies[j]+"</td></tr>")
                    }
                    else {
                      $(result_location).parent().siblings("div.collection").children().first().next().next().next().children().first().next().next().children().first().children().first().next().append("<tr><td></td><td></td><td>"+responseTxt.inseccookieinfo[i].insecurecookies[j]+"</td></tr>")
                    }
                    //console.log(responseTxt.inseccookieinfo[i].insecurecookies[j])
                  }

            }
        }

        //Code to add cookies missing HttpOnly flag
        var httponlyFlagTab=false

        for (var i = 0, l = responseTxt.inseccookieinfo.length; i < l; i++) {
            if (responseTxt.inseccookieinfo[i].nonhttponlycookies.length==0) {
              continue
            }
            else {
                  if (httponlyFlagTab==false){
                  $(result_location).parent().siblings("div.collection").children().first().next().next().next().next().append("<br><div id=\"inseccookurl\" style=\"color:black\"><table><thead><tr><th>URL</th><th>Method</th><th>Cookie</th></tr></thead><tbody></tbody></table></div>")
                  httponlyFlagTab=true
                  }


                  for (var j = 0, m = responseTxt.inseccookieinfo[i].nonhttponlycookies.length;j<m ;j++) {
                    
                    if (j==0) {
                      $(result_location).parent().siblings("div.collection").children().first().next().next().next().next().children().first().next().next().children().first().children().first().next().append("<tr><td>"+responseTxt.inseccookieinfo[i].url+"</td><td>"+responseTxt.inseccookieinfo[i].method+"</td><td>"+responseTxt.inseccookieinfo[i].nonhttponlycookies[j]+"</td></tr>")
                    }
                    else {
                      $(result_location).parent().siblings("div.collection").children().first().next().next().next().next().children().first().next().next().children().first().children().first().next().append("<tr><td></td><td></td><td>"+responseTxt.inseccookieinfo[i].nonhttponlycookies[j]+"</td></tr>")
                    }

                  }

            }
        }

        //Code to add cookies missing SameSite flag
        var samesiteFlagTab=false

        for (var i = 0, l = responseTxt.inseccookieinfo.length; i < l; i++) {
            if (responseTxt.inseccookieinfo[i].nonsamesitecookies.length==0) {
              continue
            }
            else {
                  if (samesiteFlagTab==false){
                  $(result_location).parent().siblings("div.collection").children().first().next().next().next().next().next().append("<br><div id=\"inseccookurl\" style=\"color:black\"><table><thead><tr><th>URL</th><th>Method</th><th>Cookie</th></tr></thead><tbody></tbody></table></div>")
                  samesiteFlagTab=true
                  }


                  for (var j = 0, m = responseTxt.inseccookieinfo[i].nonsamesitecookies.length;j<m ;j++) {

                    if (j==0) {
                      $(result_location).parent().siblings("div.collection").children().first().next().next().next().next().next().children().first().next().next().children().first().children().first().next().append("<tr><td>"+responseTxt.inseccookieinfo[i].url+"</td><td>"+responseTxt.inseccookieinfo[i].method+"</td><td>"+responseTxt.inseccookieinfo[i].nonsamesitecookies[j]+"</td></tr>")
                    }
                    else {
                      $(result_location).parent().siblings("div.collection").children().first().next().next().next().next().next().children().first().next().next().children().first().children().first().next().append("<tr><td></td><td></td><td>"+responseTxt.inseccookieinfo[i].nonsamesitecookies[j]+"</td></tr>")
                    }

                  }

            }
        }
      }
    }
    if(statusTxt == "error")
    alert("Error: " + xhr.status + ": " + xhr.statusText);
  })
}
//Function that create a secjob by sending the secjob info entered by the tester
function sendSecJob(){
  url= "/ess/api/"+api_version+"/secjobs";
  postbody={id: 0, name: $("#secjobname").val(), vulns:[],tJobId:$("#tjobid").val(),maxRunTimeInMins:10}
  $.ajax({
        type: "POST",
        url: url,
        // The key needs to match your method's input parameter (case-sensitive).
        data: JSON.stringify(postbody),
        contentType: "application/json; charset=utf-8",
        dataType: "json",
        success: function(result){
        toast("SecJob Created Successfully!",4000);
        addToSecJobList(result.secjob);

            },
        failure: function(errMsg) {
      toast("SecJob Creation Failed! Please check your connection",4000);
      alert(errMsg);
        }
  });

}
//Function to get tjob execution status
r="";

//Function that executes the tjob associated to the secjob under execution
function executeTJob(tjobid,elem){
  url_start_exec= "/ess/api/"+api_version+"/tjobs/"+tjobid.toString()+"/exec";
  toast("Starting Executing TJob with id: "+tjobid.toString(),4000);
  start_exec=$.ajax({
        type: "GET",
        url: url_start_exec,
        // The key needs to match your method's input parameter (case-sensitive).
        dataType: "json",
        success: function(re){
        if(re.result=="IN PROGRESS"){
          toast("TJob Execution IN PROGRESS!",4000);
          tjobExecStatus(tjobid,re,elem);
        }
        else if(result.result=="FAILED"){
        }

            },
        failure: function(errMsg) {
      toast("TJob Execution Failed",4000);
      alert(errMsg);
        }
  });
}

function tjobExecStatus(tjobid,res,element){

  get_exec_progress=$.ajax({
            type: "GET",
            url: "/ess/api/"+api_version+"/tjobs/"+tjobid.toString()+"/exec/"+res.instance,
            // The key needs to match your method's input parameter (case-sensitive).
            dataType: "json",
            success: function(result1){
            r=result1.result.toString()
            console.log("out"+r)
            element.parentNode.nextSibling.nextSibling.firstChild.firstChild.innerHTML="TJob Execution Status: "+"<p style=\"color:blue\">"+r+"</p>"
            if (r=="STARTING TSS"){
              element.parentNode.nextSibling.nextSibling.firstChild.firstChild.nextSibling.firstChild.setAttribute("style","width: 10%");
            }
            else if (r=="WAITING TSS"){
              element.parentNode.nextSibling.nextSibling.firstChild.firstChild.nextSibling.firstChild.setAttribute("style","width: 20%");
            }
            else if (r=="EXECUTING TEST"){
              element.parentNode.nextSibling.nextSibling.firstChild.firstChild.nextSibling.firstChild.setAttribute("style","width: 30%");
            }
            else if (r=="FAIL"){
              element.parentNode.nextSibling.nextSibling.firstChild.firstChild.nextSibling.firstChild.setAttribute("style","width: 100%; background-color: red");
              return "FAIL"

            }
            else if (r=="ERROR"){
              element.parentNode.nextSibling.nextSibling.firstChild.firstChild.nextSibling.firstChild.setAttribute("style","width: 100%; background-color: red");
              return "ERROR"

            }
            else if (r=="SUCCESS"){
              element.parentNode.nextSibling.nextSibling.firstChild.firstChild.nextSibling.firstChild.setAttribute("style","width: 100%; background-color: green");
              showReport(element)
              return "SUCCESS"

            }
            setTimeout(tjobExecStatus(tjobid,res,element), 10000);

               },
            failure: function(errMsg) {
          toast("TJob Execution Failed",4000);
          alert(errMsg);
          r="ERROR"
            }
        });
}
//Function that creates the contents of each stage of the secjob execution
function addToSecJobList(secjob){


  retreived_secjob="<li id=\"secjob-individual\" class=\"collection-item avatar\" style=\"display: inherit\;\"><i class=\"material-icons circle\">receipt</i><span id=\"secjobid\" class=\"title\">SecJob Id: "+secjob.id+"</span><p id=\"sejobid\">SecJob Name: "+secjob.name+"<br> Associated TJob Id: "+secjob.tJobId+"</p><a href=\"#!\"class=\"secondary-content\"><i id=\"exe-sjob\" class=\"material-icons\">play_arrow</i><p>Execute</p></a></li>";

  $("#secjob-collection").append(retreived_secjob);
  $("#exe-sjob").click(function(){
        secjobExecStat="<h5 align=\"center\">SecJob Execution</h5><div class=\"collection\"><a href=\"#!\" class=\"collection-item\"><p id=\"tjobexecstat\">TJob Execution Status</p><div class=\"progress\"><div class=\"determinate\" style=\"width: 0%\"></div></div></a><a href=\"#!\" class=\"collection-item\"><p id=\"trafficanstat\">HTTP Traffic Analysis Status:</p><div class=\"progress\"><div class=\"determinate\" style=\"width: 0%\"></div></div></a><a href=\"#!\" class=\"collection-item\">Connections without SSL protection: </a><a href=\"#!\" class=\"collection-item\">Cookies set without the <i>Secure</i> attribute: </a><a href=\"#!\" class=\"collection-item\">Cookies set without the <i>HttpOnly</i> attribute: </a><a href=\"#!\" class=\"collection-item\">Cookies without <i>SameSite</i> attribute: </a></div>"
        showSecJobExecStat(this,secjobExecStat);
        executeTJob(secjob.tJobId,this);

    });
}
//Function that displays the secjob execution status panel
function showSecJobExecStat(position,exec_stats){
  $(position).parent().parent().append(exec_stats);
}


//Function that lists the created secjob upon clicking the create button of the secjob
$(document).ready(function(){
  $("#secjob-collection").hide();
  $("#create-sjob").click(function(){
      $("#when-empty").hide();
      $("#secjob-collection").show();
      sendSecJob();
  });


});
