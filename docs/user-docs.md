# ElasTest Security Service (ESS)

The ElasTest Security Service (ESS) is an ElasTest service for identifying security vulnerabilities in Web applications. ESS creates security tests that mimics the behavior of malicious users to probe a Web application to discover vulnerabilities. ESS is based on [OWASP ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project), a prominent open source web vulnerability scanner. ESS not only supports the detection of the common web application vulnerabilities such as cross-site scripting, SQL injection etc., but also [replay attacks](https://pdfs.semanticscholar.org/270c/cf24e8be8421515f5121600f248e841f424d.pdf?_ga=2.125276362.151869347.1515086898-1552517986.1515086898) and cross-site script inclusion.

## Features
The current version of ESS (v0.5.0) has the following features.
1. A web-based GUI for providing the details of the Web application under test
2. Support for detecting [common Web application security weaknesses](https://www.owasp.org/index.php/Top_10-2017_Top_10)
2. Supports the detection of insecure cookies that can be stolen using [SSL Stripping attacks](https://paladion.net/ssl-stripping-revisiting-http-downgrading-attacks/) and [Cross-Site Scripting attacks](https://en.wikipedia.org/wiki/Cross-site_scripting), and facilitates [Cross-Site Request Forgery attacks](https://en.wikipedia.org/wiki/Cross-site_request_forgery)

The future releases of ESS will support the detection of:
1. Vulnerabilities enabling cross-origin state inference attacks
2. Vulnerabilities enabling replay attacks

## How to launch ESS

Elastest can be launched during the execution of a TJob. The following demo explains how this can be done.
1. Create a new TJob under a new Project in TORM with the following configuration:
  (a.) TJob name: ESS demo,
  (b.) Current SuT: None,
  (c.) Environment Docker Image: dockernash/test-tjob-ess,
  (d.) Commands: python fteaching-tjob.py example

2. Leave all the other inpur fields blank and tick the checkboxes for ESS and EUS under the Test Support Services section.
3. Click Save
4. Click the execute button
5. The security alters for the SuT will be displayed under the ess section

## Basic usage
### Scanning a web site using ESS
A tester can launch ESS from the "Test Support Services" tab of the ElasTest Web-GUI. The steps are as follows:
1. Start TORM and load the Web-GUI of TORM in the Web browser

![][TORM GUI]

2. Click on the "Test Support Services" side panel option

![][Click TSS]

3. From the drop down list, select "ESS" and click the button "Create Instance"

![][Launch ESS]

4. Wait until the ESS instance is completely ready

![][Load ESS]

5. Click on the "View Service Details" icon

![][View Details]

6. Scroll down to see the Web-GUI of ESS

![][ESS GUI]

7. Enter the URL of the Web site that must be tested using ESS

![][Enter SUT URL]

8. Wait until the Spidering and Active Scan completes

![][ESS Progress]

9. Check the results generated

![][ESS Results]

10. Click on each Alert to see the details

![][Result Details]


[TORM GUI]: https://i.imgur.com/WYUlN2G.png
[Click TSS]: https://i.imgur.com/ZB8G0Kv.png
[Launch ESS]: https://i.imgur.com/OAQxRpA.png
[Load ESS]: https://i.imgur.com/ejDpBn8.png
[View Details]: https://i.imgur.com/9rSYw8F.png
[ESS GUI]: https://i.imgur.com/WYUlN2G.png
[Enter SUT URL]: https://i.imgur.com/5E063n4.png
[ESS Progress]: https://i.imgur.com/m0jrUMV.png
[ESS Results]: https://i.imgur.com/ylpAUUJ.png
[Result Details]: https://i.imgur.com/SQli10g.png

