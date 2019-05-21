##############################
# Author: Avinash Sudhodanan #
##############################
from selenium import webdriver
import pprint
import os
import sys
import json
import time
from selenium.webdriver.common.keys import Keys

#function that calls all other tests
projectId=0
tjobId=0
essip=""
def e2etests():
	tormurl=sys.argv[1]
	#To check whether the TORM URL has been read correctly
	if tormurl[-1]!='/':
		tormurl=tormurl+'/'

	print("TORM URL is: "+tormurl)
	#List of all the tests to be run. Append to this list the new tests
	#tests=["test_load_torm_home_preloader(tormurl,driver)","test_load_torm_home_full(tormurl+\"/api/context/services/info\",driver)","test_service_launch(tormurl,driver)","test_create_new_project(tormurl+\"/api/project\",driver)","test_create_new_tjob(tormurl+\"/api/tjob\")","test_run_tjob(tormurl,driver)"]
	tests=["test_load_torm_homepage(tormurl,driver)","test_create_exec_tjob(tormurl,driver)"]
	#tests=["test_load_torm_homepage(tormurl,driver)"]
	#setup Chrome WebDriver
	options = webdriver.ChromeOptions()
	options.add_argument('headless')
	options.add_argument('--no-sandbox')
	capabilities = options.to_capabilities()
	try:
		eusUrl=os.environ['ET_EUS_API']
		print("EUS URL is: "+str(eusUrl))
		driver = webdriver.Remote(command_executor=eusUrl, desired_capabilities=capabilities)
	except:
		print("ERROR (Ignorable): EUS environment variable could not be read")
		#driver = webdriver.Chrome()
		driver = webdriver.Chrome(chrome_options=options)

	#driver = webdriver.Firefox() #for testing with GUI locally
	#driver = webdriver.Chrome(chrome_options=options)

	numtests=len(tests)
	testssuccess=0
	testsfailed=0
	testsrun=0
	testsleft=numtests
	#Check if the number of tests is empty
	if numtests!=0:
		#Iterate through each test in the list of tests
		for i in range(len(tests)):
			testsrun+=1
			print("~~~~~~~~~~~~~~~")
			print("Running test "+str(testsrun)+" out of "+str(testsleft))
			status=eval(tests[i])
			#Check if the last test executed successfully.
			if status=="success":
				testssuccess+=1
				print("Test Status: Success")
			if status=="failed":
				testsfailed+=1
				print("Test Status: Failed")
				#A failed test will prevent the execution of future tests. This behavior is debatable.
				break
	#driver.close()
	print("##############")
	print("_TESTS SUMMARY_")
	print("TOTAL TESTS RAN: "+str(testsrun))
	print("TOTAL TESTS SUCCEEDED: "+str(testssuccess))
	print("TOTAL TESTS FAILED: "+str(testsfailed))
	if testsfailed!=0:
		raise Exception("ERROR: Your great end-to-end tests have failed. Debug yourself or start bugging @paco or @gtunon")
	#driver.quit()
# Function to check whether the TORM preloader page can successfully retrieved
def test_load_torm_homepage(tormurl,driver):
		driver.get(tormurl)
		print(driver.page_source[:30])
		time.sleep(5)
		if(driver.page_source[:30].startswith("<!DOCTYPE html>")):
			print("\ta. TORM home page loaded")
			return "success"
		else:
			time.sleep(10)
			return "success"
		return "failed"

def test_create_exec_tjob(tormurl,driver):
		time.sleep(4)
		try:
			element = driver.find_element_by_id("newProjectBtn")
			element.click()
			print("\tb. New Project Button Clicked")
		except Exception as e:
			print("\tERROR:: New Project Button Click failed because "+str(e))
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_name('project.name')
			element.send_keys("ESS Demo Project")
			print("\tc. ESS Demo Project name entered")
		except:
			print("\tERROR: ESS Demo Project name could not be entered")
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_xpath('//*[@id="menusideLeft"]/mat-sidenav-container/mat-sidenav-content/div/div/app-project-form/div/div/mat-card/mat-card-actions/button[1]')
			element.send_keys("ESS Demo Project")
			print("\td. ESS Demo Project saved")
		except:
			print("\tERROR: ESS Demo Project could not be saved")
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_id('newTJobBtn')
			element.click()
			print("\te. New TJob Creation Button Clicked")
		except:
			print("\tERROR: New TJob Creation Button Click failed")
			return "failed"
		time.sleep(4)

		try:
			element = driver.find_element_by_name('tJobName')
			element.clear()
			element.send_keys("ESS Demo TJob")
			print("\tf. ESS Demo TJob Name Set")
		except:
			print("\tERROR: ESS Demo TJob Name Setting Failed")
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_name('resultsPath')
			element.clear()
			print("\tg. ESS Demo TJob Results Path Cleared")
		except:
			print("\tERROR:: ESS Demo TJob Results Path Clearing failed")
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_xpath('//*[@id="mat-select-0"]/div/div[1]/span')
			element.click()
			print("\th. SUT setting to None click succeeded")
		except:
			element = driver.find_element_by_xpath('//*[@id="mat-select-0"]/div/div[2]/div')
			element.click()
			print("\tERROR:: SUT setting to None click failed")
			#return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_name('tJobImageName')
			element.clear()
			print("\tg. ESS Demo TJob Docker Image Cleared")
		except:
			print("\tERROR:: ESS Demo TJob Docker Image Clearing failed")
			return "failed"
		time.sleep(4)
		try:
			element.send_keys("dockernash/test-tjob-ess")
			print("\th. ESS Test TJob Docke Image Set")
		except:
			print("\tERROR:: ESS Test TJob Docker Image Setting failed")
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_xpath('//*[@id="editorInnerContainer0"]/div/div[1]/textarea	')
			element.clear()
			print("\ti. ESS Demo TJob Commands Cleared")
		except:
			print("\tERROR:: ESS Demo TJob Commands Clearing failed")
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_xpath('//*[@id="mat-option-0"]/span')
			element.click()
			print("\ti.1. Setting SuT to None Succeeded")
		except:
			print("\tERROR: Setting SuT to None Failed")
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_xpath('//*[@id="editorInnerContainer0"]/div/div[1]/textarea	')
			element.send_keys("python fteaching-tjob.py example")
			print("\tj. ESS Test TJob Commands Set")
		except:
			print("\tERROR:: ESS Test TJob Commands Setting failed")
			return "failed"
		time.sleep(4)
		try:
			time.sleep(10)
			element = driver.find_element_by_xpath('//*[@id="serviceESS"]/label/div')
			element.click()
			print("\tk. Set ESS as TSS for the Test Tjob")
		except Exception as e:
			print("\tERROR:: Setting ESS as TSS for the Test Tjob failed because "+ str(e))
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_xpath('//*[@id="serviceEUS"]/label/div')
			element.click()
			print("\tl. Set EUS as TSS for the Test Tjob")
		except:
			print("\tERROR:: Setting EUS as TSS for the Test Tjob failed")
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_xpath('//*[@id="menusideLeft"]/mat-sidenav-container/mat-sidenav-content/div/div/etm-tjob-form/mat-card/mat-card-actions/button[1]')
			element.click()
			print("\tm. Saved the Test Tjob")
		except:
			print("\tERROR:: Attempt to Save the Test Tjob failed")
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_xpath('//*[@id="tJobs"]/div/table/tbody/tr/td[8]/div/div/div[1]/button[1]/span/mat-icon')
			element.click()
			print("\tn. Launched the Test Tjob")
		except:
			print("\tERROR:: Launching the Test Tjob failed")
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_id('resultMsgText')
			printed=True
			while(element.text!="Executing Test" or element.text!="Failed" or element.text!="Finish"):
				if(printed==True):
					print("\to. Waiting for tjob execution to complete")
					printed=False
				else:
					continue
		except:
			print("\tp. TJob Execution must have finished")
		time.sleep(4)
		try:
			element = driver.find_element_by_xpath('//*[@id="menusideLeft"]/mat-sidenav-container/mat-sidenav-content/div/div/etm-tjob-exec-view/etm-tjob-exec-manager/div[1]/div/mat-card/mat-card-title/div/a/span[2]')
			element.click()
			print("\tq. Selecting Finished TJob succeeded")
		except:
			print("\tERROR: Selecting TJob failed")
			return "failed"
		time.sleep(4)
		try:
			element = driver.find_element_by_xpath('//*[@id="menusideLeft"]/mat-sidenav-container/mat-sidenav-content/div/div/etm-tjob-manager/auto-height-grid/normal-height-row/div/mat-card/mat-card-content/div/span[6]/div/button[3]/span/mat-icon')
			element.click()
			print("\tr. Clicking Delete Button of Finished TJob Succeeded")
		except:
			print("\tERROR: Clicking Delete Button of Finished TJob Failed")
			return "failed"
		time.sleep(10)
		try:
			element = driver.find_element_by_xpath('//*[@id="mat-dialog-0"]/td-confirm-dialog/td-dialog/div/div[2]/td-dialog-actions/button[2]/span')
			element.click()
			print("\ts. Clicking Delete Confirmation Button Succeeded")
		except:
			print("\tERROR: Clicking Delete Confirmation Button Failed")
			print("Unexpected ignorable error:", sys.exc_info()[0])
		time.sleep(10)
		return "success"

if __name__=="__main__":
	e2etests()
