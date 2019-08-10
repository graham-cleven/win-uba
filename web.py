from flask import Flask, render_template
from siem import Siem

app = Flask(__name__)

@app.route('/')
def index():
    data = Siem().funcName()
    return render_template('index.html', data=data)

if __name__ == '__main__':
    app.run(host="10.6.96.3")
