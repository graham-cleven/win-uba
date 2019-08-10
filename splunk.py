import sys
import base64
import time
import splunklib.results as results
import splunklib.client as client

class Splunk:
    def __init__(self): 

        HOST = "localhost"
        PORT = 8089
        USERNAME = "root" 
        PASSWORD = base64.b64decode("b3ZlclRoZU1vb24uNjY2")

        service = client.connect(
                host=HOST,
                port=PORT,
                username=USERNAME,
                password=PASSWORD)

        self.service=service

    def query(self, search):
        query = "search " + search 
        kwargs_normalsearch = {"exec_mode": "normal"}
        job = self.service.jobs.create(query, **kwargs_normalsearch)

        while True:
            while not job.is_ready():
                pass

            if job["isDone"] == "1":
                break
                # time.sleep(2)
        
        resp = []
        for result in results.ResultsReader(job.results()):
            resp.append(result)

        return resp
