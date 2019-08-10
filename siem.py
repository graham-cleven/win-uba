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

# for each logon, find corposponding logoff
for logon in logonObjs:
    for logoff in logoffObjs:

        # if Logon_ID in logon event matches Logon_ID in logoff event
        # and machine matches
        # if ((logon[4] == logoff[2] or logon[5] == logoff[2]) and logon[1] == logoff[3]):

        # machine matches
        if logon[1] == logoff[3]:

            # find corposponding logoff and logon
            if logon[4] == logoff[2]:
                targetLogoff = logoff[2]
                targetLogon = logon[4]

            # find corposponding split logon
            targetSplitLogon = 

    # merge events into sessions
    ses = {'logon' : logon, 'logoff' : logoff}

    # attach to master sessions list
    sessions.append(ses)

for ses in sessions:
    print(ses)

