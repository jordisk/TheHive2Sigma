import requests
import json
import sys
from ruamel.yaml import YAML
from collections import OrderedDict
import datetime

now = datetime.datetime.now()

#Config

thehive_url = '' # The hive URL including port
thehive_api = '' #Api key for The Hive
thehive_case = '' # The Hive case id (20 chars)


def getKeysByValue(dictOfElements, valueToFind):
    listOfKeys = list()
    listOfItems = dictOfElements.items()
    for item  in listOfItems:
        if item[1] == valueToFind:
            listOfKeys.append(item[0])
    return  listOfKeys  
 
def getKeysByValues(dictOfElements, listOfValues):
    listOfKeys = list()
    listOfItems = dictOfElements.items()
    for item  in listOfItems:
        if item[1] in listOfValues:
            listOfKeys.append(item[0])
    return  listOfKeys 



def getCaseData():
	headers = {
    'Authorization': 'Bearer '+ thehive_api,
	}
	response = requests.get(thehive_url +'/api/case/'+thehive_case, headers=headers)
	#print response.content
	json_data = json.loads(response.content)
	getCaseData.case_id = json_data['caseId']
	getCaseData.case_title = json_data['title']
	getCaseData.case_url = thehive_url + '/index.html#/case/' + thehive_case + '/details'
	getCaseData.case_createdBy = json_data['createdBy']



def getObservables():
	headers = {
    	'Authorization': 'Bearer '+ thehive_api,
    	'Content-Type': 'application/json',
	}

	data = ' {"query": { "_parent": { "_type": "case", "_query": { "_id": "'+thehive_case+'" } } } } '

	response = requests.post(thehive_url +'/api/case/artifact/_search', headers=headers, data=data)
	#print response.content
	json_data = json.loads(response.content)

	#Create dictionary
	getObservables.observables = {}
	#For any observable in json data, wirte data and dataType to the dictionary
	for observable in json_data:
		#print (observable["dataType"], obserbable["data"])
		getObservables.observables[observable["data"]] = observable["dataType"]
	#print ip observables
	#print observables.keys()[obserbables.values().index('ip')]
	
	#Count number of type of observables and number od ofservables writen to the sigma rule
	obtypes = []
	for i in getObservables.observables:
		obtypes.append(getObservables.observables[i])
	getObservables.countTypes = len(list(set(obtypes)))
	getObservables.counter = 0



def createSigmaJson():

	if getObservables.countTypes == 0:
		print "[ERROR] No observables found on case"
		return
	elif getObservables.countTypes > 1:
		sigma_rule = "action: global \ntitle: Case " + str(getCaseData.case_id)+ " " + getCaseData.case_title +"\n"

	else:
		sigma_rule = "title: Case " + str(getCaseData.case_id)+ " " + getCaseData.case_title +"\n"
	
	#Start Sigma
	sigma_rule += "status: experimental\n"
	sigma_rule += "description: Detects Observables based on Case " + str(getCaseData.case_id)+" from TheHive\n"
	sigma_rule += "author: " + getCaseData.case_createdBy + "\n"
	sigma_rule += "references:\n    - "+ getCaseData.case_url + "\n"
	sigma_rule += "date: " + now.strftime("%Y/%m/%d") + "\n"
	#Maybe add tags from case

	if getObservables.countTypes == 1:
		pass
	elif getObservables.counter <= getObservables.countTypes:
		sigma_rule += "---\n"
	else:
		print "[Error]"

	#CREATES SIGMA FOR IP addresses
	listOfKeys = getKeysByValue(getObservables.observables, 'ip')
	if not listOfKeys :
		pass
		
	else:
		sigma_rule += "logsource:\n"
		sigma_rule += "    category: firewall" + "\n"
		sigma_rule += "detection:" + "\n"
		
		sigma_rule += "    outgoing: " + "\n"
		sigma_rule += "        dst_ip:"+"\n"
		#Iterate over the list of keys
		for key in listOfKeys:
			sigma_rule += "            - '"+ key+"'\n"
		
		sigma_rule += "    incoming: " + "\n"
		sigma_rule += "        src_ip:"+"\n"
		#Iterate over the list of keys
		for key in listOfKeys:
			sigma_rule += "            - '"+ key+"'\n"
		
		sigma_rule += "    condition: 1 of them" + "\n"

		#Add lines to create antoher yaml document
		getObservables.counter += 1
		if getObservables.counter < getObservables.countTypes:
			sigma_rule += "---\n"
		else:
			pass



	#CREATES SIGMA FOR fqdn and domains
	listOfKeys = getKeysByValues(getObservables.observables, ['fqdn', 'domain'] )
	if not listOfKeys :
		pass
		
	else:
		sigma_rule += "logsource:\n"
		sigma_rule += "    category: dns" + "\n"
		sigma_rule += "detection:" + "\n"
		sigma_rule += "    selection: " + "\n"
		sigma_rule += "        query: " + "\n"

		#Iterate over the list of keys
		for key in listOfKeys:
			sigma_rule += "            - '"+ key+"'\n"
		sigma_rule += "    condition: selection" + "\n"

		#Add lines to create antoher yaml document
		getObservables.counter += 1
		if getObservables.counter < getObservables.countTypes:
			sigma_rule += "---\n"
		else:
			pass


	#CREATES SIGMA for user agents
	listOfKeys = getKeysByValues(getObservables.observables, 'user-agent')
	if not listOfKeys :
		pass
		
	else:
		sigma_rule += "logsource:\n"
		sigma_rule += "    category: proxy" + "\n"
		sigma_rule += "detection:" + "\n"
		sigma_rule += "    selection1: " + "\n"
		sigma_rule += "        UserAgent: " + "\n"

		#Iterate over the list of keys
		for key in listOfKeys:
			sigma_rule += "            - '"+ key+"'\n"
		sigma_rule += "    condition: selection1" + "\n"

		#Add lines to create antoher yaml document
		getObservables.counter += 1
		if getObservables.counter < getObservables.countTypes:
			sigma_rule += "---\n"
		else:
			pass


	#CREATES SIGMA for Registry keys
	listOfKeys = getKeysByValues(getObservables.observables, 'registry')
	if not listOfKeys :
		pass
		
	else:
		sigma_rule += "logsource:\n"
		sigma_rule += "    product: windows" + "\n"
		sigma_rule += "    service: sysmon" + "\n"
		sigma_rule += "detection:" + "\n"
		sigma_rule += "    selection2: " + "\n"
		sigma_rule += "        EventID: " + "\n"
		sigma_rule += "            - 13" + "\n"
		sigma_rule += "            - 12" + "\n"
		sigma_rule += "            - 14" + "\n"
		sigma_rule += "        TargetObject: " + "\n"
		#Iterate over the list of keys
		for key in listOfKeys:
			sigma_rule += "            - '"+ key+"'\n"
		sigma_rule += "    condition: selection2" + "\n"

		#Add lines to create antoher yaml document
		getObservables.counter += 1
		if getObservables.counter < getObservables.countTypes:
			sigma_rule += "---\n"
		else:
			pass


	##### WORKING #####
	#CREATES SIGMA for Process
	listOfKeys = getKeysByValues(getObservables.observables, 'process')
	if not listOfKeys :
		pass
		
	else:
		sigma_rule += "logsource:\n"
		sigma_rule += "    product: windows" + "\n"
		sigma_rule += "    service: sysmon" + "\n"
		sigma_rule += "detection:" + "\n"
		sigma_rule += "    selection3: " + "\n"
		sigma_rule += "        EventID: 1" + "\n"
		sigma_rule += "        TargetImage: " + "\n"
		#Iterate over the list of keys
		for key in listOfKeys:
			sigma_rule += "            - '*\\"+ key+"'\n"
		sigma_rule += "    condition: selection3" + "\n"

		#Add lines to create antoher yaml document
		getObservables.counter += 1
		if getObservables.counter < getObservables.countTypes:
			sigma_rule += "---\n"
		else:
			pass


	print sigma_rule

if __name__ == '__main__':
	getCaseData()
	getObservables()
	createSigmaJson()
	
