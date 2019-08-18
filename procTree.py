from splunk import Splunk
from anytree import Node, RenderTree

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

# get list of PIDs
pids = []
for proc in procs:
    pids.append(proc['New_Process_ID'])

for pid in pids:
    parent = Node(pid)

    for proc in procs:
        if proc['Creator_Process_ID'] == pid:
            Node(proc['New_Process_ID'], parent=parent)

    for pre, fill, node in RenderTree(parent):
        print("%s%s" % (pre, node.name))

"""
#tree = [[{'layer' : 0, 'name' : 'name', 'time' : 1 }, {'layer' : 1...}]]

# verify that process is parent 
parents = []
for proc in procs:
    def findParent():
        for pproc in procs:
            if proc['Creator_Process_ID'] == pproc['New_Process_ID']:
                return 

            # start new parent branch
            parent = {'parent' : {'name' : proc['New_Process_Name']}, 'children' : []}
            
            # attach children
            for ppproc in procs:
                if ppproc['Creator_Process_ID'] == proc['New_Process_ID']:
                    child = {'name' : ppproc['New_Process_Name']}
                    parent['children'].append(child)

        parents.append(parent)

    findParent()

print(parents)
"""
