from splunk import Splunk
from datetime import datetime
import utils
from config import config as cf


class Siem:
    def __init__(self):
        # connect to Splunk server
        self.splunkServer = Splunk()

    def getNet(self, hostname, stime, etime):
        """
        Function corrorlates network activity to 
        logon session by host & time
        """
        net = {}

        # query for DHCP correlation
        query = "index={} sourcetype={} hostname={} | head 1 \
                | table IP".format(
            cf["net-index"], cf["dhcp-type"], hostname
        )
        IP = self.splunkServer.query(query)[0]["IP"]

        # fuzz time
        time = utils.fuzzTime(stime, etime, cf["net-lat"])

        # inbound SSH
        query = "index={} dest_ip={} sourcetype=bro_ssh \
                earliest={} latest={} | sort 0 _time \
                | table  _indextime, src_ip".format(
            cf["net-index"], IP, time[0], time[1]
        )
        ssh = utils.makeEpoch(self.splunkServer.query(query))

        # outgoing http
        query = "index={} src_ip={} sourcetype=bro_http \
                earliest={} latest={} | sort 0 _time \
                | table _indextime, dest_ip, dest_host".format(
            cf["net-index"], IP, time[0], time[1]
        )
        http = utils.makeEpoch(self.splunkServer.query(query))

        net.update(ssh=ssh, http=http)

        return net

    def getProcess(self, logonID, host, stime, etime):
        """
        function takes logonID (hex), host, start time, and end time
        returns all processes pinned to that logon id at that time
        """

        # fuzz time
        time = utils.fuzzTime(stime, etime, cf["host-lat"])

        # setup query
        query = "index={} {}=4688 Logon_ID={} host={} \
                earliest={} latest={} | sort 0 _time \
                | table _indextime Creator_Process_Name, New_Process_Name \
                Creator_Process_ID, New_Process_ID".format(
            cf["host-index"], cf["field-event"], logonID, host, time[0], time[1]
        )
        procs = self.splunkServer.query(query)

        # tree = [{'parent' : {'name' : 'cmd.exe'}, 'children' : [{'name' : 'conhost.exe', 'children' : [{'name': 'conhostchild.exe'}, {'name' : 'conhostchild2.exe', 'children' : [{'name' : 'conhostchild2child.exe'}]}]}, {'name' : 'tasklist.exe'}] }]

        # generic find child funciton
        def findChild(procs, Creator_Process_ID):
            children = []
            for proc in procs:
                if proc["Creator_Process_ID"] == Creator_Process_ID:
                    child = {
                        "name": proc["New_Process_Name"],
                        "New_Process_ID": proc["New_Process_ID"],
                        "children": [{}],
                    }
                    children.append(child)
            if len(children) > 0:
                return children
            else:
                return 0

        # get list of PPIDS
        ppids = set()
        for proc in procs:
            ppids.add(proc["Creator_Process_ID"])

        # parents list contains top level PPIDs (0x8c in test db)
        # parents = ['0x2b4', '0x220', '0x2e8', '0x1e30', '0x398', '0x3d4']
        parents = []
        for ppid in ppids:
            parentFlag = True
            for proc in procs:
                if proc["New_Process_ID"] == ppid:
                    parentFlag = False
            if parentFlag == True:
                parents.append(ppid)

        # return procs[3]

        # populate parents list
        parentsMeta = []
        for parent in parents:
            for proc in procs:
                if proc["Creator_Process_ID"] == parent:
                    parentObj = {
                        "parent": {
                            "name": proc["New_Process_Name"],
                            "New_Process_ID": proc["New_Process_ID"],
                        }
                    }
                    parentsMeta.append(parentObj)

        # child l1
        for parent in parentsMeta:
            child = findChild(procs, parent["parent"]["New_Process_ID"])
            if child:
                parent.update(children=child)

                # l2
                for child in parent["children"]:
                    cchild = findChild(procs, child["New_Process_ID"])
                    if cchild:
                        child.update(children=cchild)

                        # l3
                        for cchild in child["children"]:
                            ccchild = findChild(procs, cchild["New_Process_ID"])
                            if ccchild:
                                cchild.update(children=ccchild)

        return parentsMeta

    def getSessions(self, user, stime, etime):
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

        # setup query
        query = "index={} {} earliest={} latest={} {} IN (4624, \
                    4634, 4647) \
                    | table _indextime, Logon_Type, Account_Name \
                    Logon_ID, Linked_Logon_ID, TaskCategory, host, \
                    Elevated_Token".format(
            cf["host-index"], user, stime, etime, cf["field-event"]
        )
        self.logs = self.splunkServer.query(query)

        # initial logon & logoff lists
        logonObjs = []
        logoffObjs = []

        # create master list of logons and logoffs
        for log in self.logs:

            if log["TaskCategory"] == "Logon":
                # extract & structure login data
                logObj = [
                    datetime.fromtimestamp(float(log["_indextime"])).strftime(
                        "%d %b %y %H:%M:%S"
                    ),
                    log["host"],
                    log["Account_Name"][-1],
                    log["Logon_Type"],
                    log["Logon_ID"][-1],
                    log["Linked_Logon_ID"],
                    log["Elevated_Token"],
                    log["_indextime"],
                ]

                # append login event to master login list
                logonObjs.append(logObj)

            if log["TaskCategory"] == "Logoff":
                # extract logoff data
                logObj = [
                    datetime.fromtimestamp(float(log["_indextime"])).strftime(
                        "%d %b %y %H:%M:%S"
                    ),
                    log["Account_Name"],
                    log["Logon_ID"],
                    log["host"],
                    log["_indextime"],
                ]

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


# print(Siem().getProcess("0xB12A9", "DESKTOP-IUAO9R7", "1565479428", "1565479495"))
