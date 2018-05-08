# Standalone script to determine fetch_sizes of ct logs

import requests

logs = requests.get('https://www.gstatic.com/ct/log_list/log_list.json').json()

for log in logs["logs"]:
    try:
        entries = requests.get("https://%sct/v1/get-entries?start=0&end=1024" % log["url"], timeout=10).json()
    except Exception, e:
        print "%s exception %s" % (log["url"], str(e))
    else:
        print "%s supports fetch_size of %s" % (log["url"],len(entries["entries"]))

