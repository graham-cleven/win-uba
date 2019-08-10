from flask import Flask, render_template
from siem import Siem

app = Flask(__name__)

@app.route('/<username>')
def index(username):
    data = Siem().getSessions(username)
    # processes = Siem().getProcess(data[3], data[0], data, data)
    return render_template('index.html', data=data)

@app.route('/session/<logonID>/<host>/<stime>/<etime>')
def session(logonID, host, stime, etime):
    processes = Siem().getProcess(logonID, host, stime, etime)
    return str(processes)
    

if __name__ == '__main__':
    app.run(host="0.0.0.0", debug=True)
