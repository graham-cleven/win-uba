import sys
import base64
import time
import splunklib.results as results
import splunklib.client as client
from config import config

class Splunk:
    def __init__(self): 

        HOST = config['splunk-host']
        PORT = config['splunk-port']
        USERNAME = config['splunk-user'] 
        PASSWORD = base64.b64decode(config['splunk-pwd'])

        service = client.connect(
                host=HOST,
                port=PORT,
                username=USERNAME,
                password=PASSWORD)

        self.service=service

    def query(self, search):
        query = "search " + search 
        kwargs_normalsearch = {"exec_mode": "normal", "count": 0}
        job = self.service.jobs.create(query, **kwargs_normalsearch)

        while True:
            while not job.is_ready():
                pass
            
            stats = {"isDone": job["isDone"],
                "doneProgress": float(job["doneProgress"])*100,
                "scanCount": int(job["scanCount"]),
                "eventCount": int(job["eventCount"]),
                "resultCount": int(job["resultCount"])}

            status = ("\r%(doneProgress)03.1f%%   %(scanCount)d scanned   "
              "%(eventCount)d matched   %(resultCount)d results") % stats

            # sys.stdout.write(status)
            # sys.stdout.flush()
            if stats["isDone"] == "1":
                # sys.stdout.write("\n\nDone!\n\n")
                break
                time.sleep(2)

        resp = []
        for result in results.ResultsReader(job.results(count=0)):
            resp.append(result)

        return resp
