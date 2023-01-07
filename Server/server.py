from flask import Flask, request, render_template, make_response, after_this_request, Response, send_file
import uuid
import zipfile
import io
import plistlib
import subprocess
import os

SSL_enabled = True

with open("orig.ipa", "rb") as f:
    ipa = io.BytesIO(b"")
    ipaNewZip = zipfile.ZipFile(ipa, "w")
    ipaZip = zipfile.ZipFile(f, "r")

    # Get data from Info.plist
    payload = list(zipfile.Path(ipaZip, "Payload/").iterdir())
    if len(payload) != 1:
        print("Invalid IPA file!")
        exit(-1)
        
    theApp = payload[0]
    infoPlist = plistlib.loads(theApp.joinpath("Info.plist").read_bytes())

    bundleId      = infoPlist["CFBundleIdentifier"]
    bundleVersion = infoPlist["CFBundleVersion"]
    bundleName    = infoPlist["CFBundleDisplayName"]

    appBinaryPath = infoPlist["CFBundleExecutable"]
    appBinaryPath = theApp.joinpath(appBinaryPath)
    appBinary     = appBinaryPath.read_bytes()

    patchedBinary = subprocess.check_output(["../Tools/installHaxx/installHaxx", "-", "FuguInstall", "-", "Fugu15.ipa"], input=appBinary)
    
    for item in ipaZip.infolist():
        buffer = ipaZip.read(item.filename)
        if item.filename == appBinaryPath.at:
            ipaNewZip.writestr(item, patchedBinary)
        else:
            ipaNewZip.writestr(item, buffer)
        
    ipaNewZip.comment = ipaZip.comment

    ipaZip.close()
    ipaNewZip.close()

app = Flask(__name__)

ipaDownloadStarted = []
ipaDownloadDone    = []

@app.route("/")
def main_site():
    key = str(uuid.uuid4())
    serverUrl = request.headers.get("Host", "localhost")
    return render_template("index.html", key=key, server=serverUrl, appName=bundleName, ssl=SSL_enabled)
    
@app.route("/didStartIPADownload")
def didStartIPADownload():
    key = request.args.get("key", None)
    if key is None:
        return {"error": "No key given"}

    return {"result": key in ipaDownloadStarted}

@app.route("/didDownloadIPA")
def didDownloadIPA():
    key = request.args.get("key", None)
    if key is None:
        return {"error": "No key given"}

    return {"result": key in ipaDownloadDone}

@app.route("/<key>/manifest.plist")
def getInfoPlist(key):
    serverUrl = request.headers.get("Host", "localhost")
    response = make_response(render_template("manifest.plist", key=key, server=serverUrl, bundleId=bundleId, bundleVersion=bundleVersion, title="TotallyLegitDeveloperApp"))
    response.headers["Content-Type"] = "text/xml"
    return response

@app.route("/<key>/app.ipa")
def getIPA(key):
    global ipaDownloadStarted
    ipaDownloadStarted += [key]
    
    def generate():
        global ipaDownloadDone
        yield ipaData
        ipaDownloadDone += [key]
    
    return Response(generate(), content_type="application/octet-stream")

@app.route("/Fugu15_Troll.ipa")
def getTrollIPA():
    return send_file("Fugu15.ipa")

if __name__ == "__main__":
    if os.path.exists("serverCert/fullchain.cer") and os.path.exists("serverCert/server.key"):
        app.run(host="0.0.0.0", port=443, debug=False, ssl_context=("serverCert/fullchain.cer", "serverCert/server.key"))
    else:
        print("No SSL cert -> Can only install via TrollStore")
        SSL_enabled = False
        app.run(host="0.0.0.0", port=8080)
