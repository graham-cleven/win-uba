from splunk import Splunk
from anytree import Node, RenderTree

splunkServer = Splunk()

logonID = "0x5CFE8F3"
host = "DESKTOP-IUAO9R7"
time = ["1566081929", "1566081981"]

query = "index=windows EventCode=4688 Logon_ID={} host={} \
        earliest={} latest={} | table _indextime \
        Creator_Process_Name, New_Process_Name \
        Creator_Process_ID, New_Process_ID".format(
    logonID, host, time[0], time[1]
)
procs = splunkServer.query(query)

# generic find child funciton
def findChild(procs, creator_Process_ID):
    children = []
    for proc in procs:
        if proc["Creator_Process_ID"] == creator_Process_ID:
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
parents = []
for ppid in ppids:
    parentFlag = True
    for proc in procs:
        if proc["New_Process_ID"] == ppid:
            parentFlag = False
    if parentFlag == True:
        parents.append(ppid)

# populate parents list
parentsMeta = []
for parent in parents:
    for proc in procs:
        if proc["Creator_Process_ID"] == parent:
            parent = {
                "parent": {
                    "name": proc["New_Process_Name"],
                    "New_Process_ID": proc["New_Process_ID"],
                }
            }
            parentsMeta.append(parent)

p1 = Node(parentsMeta[0]["parent"]["New_Process_ID"])

for proc in procs:
    Node(proc["New_Process_ID"], parent=proc["Creator_Process_ID"])

for pre, fill, node in RenderTree(p1):
    print("%s%s" % (pre, node.name))


"""
# get list of PPIDs
ppids = []
for proc in procs:
    ppids.append(proc['Creator_Process_ID'])

pids = []
for proc in procs:
    if proc['New_Process_ID'] in ppids:
        pids.append({'pid' : proc['New_Process_ID'], 'name' : proc['New_Process_Name']})

for pid in pids:
    parent = Node(pid)

    for proc in procs:
        if proc['Creator_Process_ID'] == pid['pid']:
            Node({'pid' : proc['New_Process_ID'], 'name' : proc['New_Process_Name']}, parent=parent)

    for pre, fill, node in RenderTree(parent):
        print("%s%s" % (pre, node.name))
"""


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
