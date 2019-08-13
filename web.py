from flask import Flask, render_template
from siem import Siem

app = Flask(__name__)

@app.route('/<username>')
def index(username):
    data = Siem().getSessions(username)
    return render_template('index.html', data=data)

@app.route('/session/<logonID>/<host>/<stime>/<etime>')
def session(logonID, host, stime, etime):
    processes = Siem().getProcess(logonID, host, stime, etime)
    return render_template('processes.html', procs=processes) 

@app.route('/net/<host>/<stime>/<etime>')
def network(host, stime, etime):
    net = Siem().getNet(host, stime, etime)
    return net

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
