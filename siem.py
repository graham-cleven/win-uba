from splunk import Splunk

class Siem:
    def __init__(self):
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

        query = "index=windows earliest=-1y latest=+3years EventCode=4624 OR \
                    EventCode=4634 OR EventCode=4647 \
                    | table _indextime, Logon_Type, Account_Name \
                    Logon_ID, Linked_Logon_ID, TaskCategory, host, RecordNumber"

        # execute query
        self.logs = splunkServer.query(query) 

    def funcName(self):    

        # initial logon & logoff objects
        logonObjs = []
        logoffObjs = [] 

        # create master list of logons and logoffs
        for log in self.logs:

            if log['TaskCategory'] == 'Logon':
                # extract & structure login data 
                logObj = [int(log['_indextime']), log['host'],
                        log['Account_Name'][-1], log['Logon_Type'],
                        log['Logon_ID'][-1], log['Linked_Logon_ID']]

                # append login event to master login list
                logonObjs.append(logObj)

            if log['TaskCategory'] == 'Logoff':
                # extract logoff data
                logObj = [int(log['_indextime']), log['Account_Name'],
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

        for logon in logonObjs:
            for logoff in logoffObjs:

                # check user & machine match
                if logoff[3] == logon[1] and logoff[1] == logon[2]:

                    # find corosponding logoff
                    if logoff[2] == logon[4]:
                        session = [logon, logoff]
                        sessions.append(session) 

                    # split tokens will use Linked_Logon_ID
                   # if logoff[2] == logon[5]:
                    #    session = [logon, logoff]
                     #   sessions.append(session)

        return sessions
