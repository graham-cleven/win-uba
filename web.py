from flask import Flask, render_template, redirect
from siem import Siem
import time

app = Flask(__name__)

@app.route('/')
def index():
    return redirect("/ses/*/{}/now".format(str(int(time.time() - 3600)))) 

@app.route('/ses/<username>/<stime>/<etime>')
def ses(username, stime, etime):
    data = Siem().getSessions(username, stime, etime)
    return render_template('ses.html', data=data)

@app.route('/procs/<logonID>/<host>/<stime>/<etime>')
def session(logonID, host, stime, etime):
    processes = Siem().getProcess(logonID, host, stime, etime)
    return render_template('processes.html', procs=processes) 

@app.route('/net/<host>/<stime>/<etime>')
def network(host, stime, etime):
    net = Siem().getNet(host, stime, etime)
    return render_template('net.html', net=net)

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
