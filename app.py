from feature import FeatureExtraction
import socket
import sys
from flask import Flask, render_template, request
from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics
import warnings
import pickle
warnings.filterwarnings('ignore')

file = open("pickle/model.pkl", "rb")
gbc = pickle.load(file)
file.close()

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def main():
    return render_template("index.html")


@app.route("/port", methods=["GET", "POST"])
def port():
    if request.method == "POST":
        socket.setdefaulttimeout(0.01)
        # network = input("IP ADDRESS: ")
        network = request.form["network"]
        # startPort = int(input("START PORT: "))

        startPort = int(request.form["startPort"])
        # endPort = int(input("END PORT: "))

        endPort = int(request.form["endPort"])
        scanHost(network, startPort, endPort)
    return render_template("port.html")


def scanHost(ip, startPort, endPort):
    print('[*] Starting TCP port scan on host %s' % ip)
    # Begin TCP scan on host
    tcp_scan(ip, startPort, endPort)
    print('[+] TCP scan on host %s complete' % ip)


def tcp_scan(ip, startPort, endPort):
    for port in range(startPort, endPort + 1):
        try:
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if not tcp.connect_ex((ip, port)):
                print('[+] %s:%d/TCP Open' % (ip, port))
                tcp.close()
        except Exception:
            pass


@app.route("/phis", methods=["GET", "POST"])
def phis():
    if request.method == "POST":

        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        y_pred = gbc.predict(x)[0]
        #1 is safe
        #-1 is unsafe
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]
        # if(y_pred ==1 ):
        pred = "It is {0:.2f} % safe to go ".format(y_pro_phishing*100)
        return render_template('phis.html', xx=round(y_pro_non_phishing, 2), url=url)
    return render_template("phis.html", xx=-1)


# main()
# end = input("Press any key to close")

if __name__ == "__main__":
    app.run(debug=True)
