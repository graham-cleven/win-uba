from splunk import Splunk

splunkServer = Splunk()

logonID = "0x5CFE8F3"
host = "DESKTOP-IUAO9R7" 
time = ['1566081929', '1566081981']

query = "index=windows EventCode=4688 Logon_ID={} host={} \
        earliest={} latest={} | table _indextime \
        Creator_Process_Name, New_Process_Name \
        Creator_Process_ID, New_Process_ID"\
        .format(logonID, host, time[0], time[1])
procs = splunkServer.query(query)

#tree = [[{'layer' : 0, 'name' : 'name', 'time' : 1 }, {'layer' : 1...}]]

# verify that process is at bottom of tree
children = []
for proc in procs:
    def findChild():
        for pproc in procs:
            if proc['New_Process_ID'] == pproc['Creator_Process_ID']:
                return 
        child = {'layer' : 0, 'name' : proc['New_Process_Name'],\
                'time' : proc['_indextime']}
        children.append(child)

    findChild()

# recursively find parents
for child in children:
    def findParents():
        for proc in procs:
            if 

# if parent is already in a branch 
