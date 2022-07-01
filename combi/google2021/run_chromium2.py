import subprocess
import tempfile
import sys
import shutil
import os
import base64

pwd = os.getcwd()
with open('./sandbox_exp/exploit.html', "rb") as f:
    data = f.read()

with open("./sandbox_exp/exploit.js", "rb") as f:
    data2 = f.read()

data = data.replace(b"SBX_EXPLOIT", data2)

with open("./sandbox_exp/final.html", "wb+") as f:
    f.write(data)

#exit(1);
subprocess.check_call([pwd+'/chromium/chrome', '--headless', '--disable-gpu',
                       '--remote-debugging-port=9222', 
                       '--user-data-dir=./sandbox_exp/',
                       '--enable-logging=stderr', "--js-flags=--allow-natives-syntax",
                       'final.html'], cwd=pwd+'/sandbox_exp')

