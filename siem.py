from splunk import Splunk
from datetime import datetime
import utils

class Siem:
    def __init__(self):
        # connect to Splunk server
        self.splunkServer = Splunk()
    
    def getNet(self, hostname, stime, etime):
        
        """
        Function corrorlates network activity to 
        logon session by host & time
        """

        # setup query for DHCP correlation
        query = "index=bro sourcetype=dhcp hostname={} | head 1 \
                | table IP".format(hostname)

        # execute query / grab IP addr
        IP = self.splunkServer.query(query)[0]['IP']

        # fuzz time
        time = utils.fuzzTime(stime, etime, 20)

        # setup query against network data
        query = "index=bro dest_ip={} sourcetype=bro_ssh \
                earliest={} latest={} \
                | table  _time, src_ip".format(IP, time[0], time[1]) 
        net = self.splunkServer.query(query)
        return(str(net))

    def getProcess(self, logonID, host, stime, etime):

        """
        function takes logonID (hex), host, start time, and end time
        returns all processes pinned to that logon id at that time
        """
        
        # fuzz time 
        time = utils.fuzzTime(stime, etime, 10)

        # setup query
        query = "index=windows EventCode=4688 Logon_ID={} host={} \
                earliest={} latest={} \
                | table _indextime Creator_Process_Name, New_Process_Name" \
                .format(logonID, host, time[0], time[1])

        # execute query
        processes = self.splunkServer.query(query)
        
        procTree = []
        # procTree.update(children = ["test", "test2"])

        # extract set of parrent processes
        parents = set() 
        for proc in processes:
            parents.add(proc['Creator_Process_Name'])

        # attach children
        for parent in parents:
            branch = {"parent" : parent, "children" : []}

            # find kids and add to list after parent
            children = []
            for proc in processes:
                if parent == proc['Creator_Process_Name']:
                    children.append(proc['New_Process_Name'])

            branch.update( children=children)

            # attach branch to tree
            procTree.append(branch)

        return procTree

    def getSessions(self, user):
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

        query = "index=windows {} earliest=-1y latest=+3years EventCode=4624 OR \
                    EventCode=4634 OR EventCode=4647 \
                    | table _indextime, Logon_Type, Account_Name \
                    Logon_ID, Linked_Logon_ID, TaskCategory, host, \
                    Elevated_Token".format(user)

        # execute query
        self.logs = self.splunkServer.query(query) 

        # initial logon & logoff objects
        logonObjs = []
        logoffObjs = [] 

        # create master list of logons and logoffs
        for log in self.logs:

            if log['TaskCategory'] == 'Logon':
                # extract & structure login data 
                logObj = [datetime.fromtimestamp(float(log['_indextime'])) \
                        .strftime("%d %b %y %H:%M:%S"), \
                        log['host'], log['Account_Name'][-1], 
                        log['Logon_Type'], log['Logon_ID'][-1],
                        log['Linked_Logon_ID'], log['Elevated_Token'],
                        log['_indextime']]

                # append login event to master login list
                logonObjs.append(logObj)

            if log['TaskCategory'] == 'Logoff':
                # extract logoff data
                logObj = [datetime.fromtimestamp(float(log['_indextime'])) \
                        .strftime("%d %b %y %H:%M:%S"), \
                        log['Account_Name'], log['Logon_ID'], 
                        log['host'], log['_indextime']]

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


        self.sessions = sessions

        return sessions


# Siem().getProcess("0xB12A9", "DESKTOP-IUAO9R7", "1565479428", "1565479495")
