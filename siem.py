from splunk import Splunk

# connect to our Splunk server
splunkServer = Splunk()

# setup query
"""
Event Codes:
4624 - New login
4634 - An account was logged off (non-interactive)
4647 - User initiated logoff

Fields:
TaskCategory - Logon or Logoff
Account_Name[0]/[1] - Logon Server (not used yet) / username
Logon_ID[0]/[1] - Subject Logon_ID (not used) / Logon_ID
"""

query = "index=windows EventCode=4624 OR \
            EventCode=4634 OR EventCode=4647 \
            | table _indextime, Logon_Type, Account_Name \
            Logon_ID, Linked_Logon_ID, TaskCategory, host"

# execute query
logs = splunkServer.query(query) 

# initial logon & logoff objects
logonObjs = []
logoffObjs = [] 

# create master list of logons and logoffs
for log in logs:
    if log['TaskCategory'] == 'Logon':
        # extract & structure login data 
        logObj = [log['_indextime'], log['host'],
                log['Account_Name'][1], log['Logon_Type'],
                log['Logon_ID'][1], log['Linked_Logon_ID']]

        # append login event to master login list
        logonObjs.append(logObj)

    if log['TaskCategory'] == 'Logoff':
        # extract logoff data
        logObj = [log['_indextime'], log['Account_Name'],
                log['Logon_ID'], log['host']]

        # append logoffs to master list
        logoffObjs.append(logObj)

# merge logon and logoff lists to create sessions
"""
Logoff will terminate split token
ex:
['t', 'DESKTOP-IUAO9R7', 'usr', '2', '0x13F9908', '0x13F98E9']
['t', 'DESKTOP-IUAO9R7', 'usr', '2', '0x13F98E9', '0x13F9908']
['t', 'usr', '0x13F9908', 'DESKTOP-IUA09R7']
"""

# initialize sessions container
sessions = []

# merge logons with split tokens
for logon in logonObjs:
    for logonSplit in logonObjs:
        if logon[4] == logonSplit[5]:

            for ses in sessions:
                if ses[0] == logonSplit and ses[1] == logon:
                    break 

            # merge splits and add to set 
            logonCombined = [logon, logonSplit]
            sessions.append(logonCombined)

# {'logon' : logon, 'logon-split' : logon-split, 'logoff' : logoff}


for ses in sessions:
    print(ses)

