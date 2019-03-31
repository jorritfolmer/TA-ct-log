# encoding = utf-8

import os
import sys
import time
import datetime
from ctl.ctl2splunk import CTL2Splunk

def validate_input(helper, definition):
    """Implement your own validation logic to validate the input stanza configurations"""
    # This example accesses the modular input variable
    # ctl_endpoint = definition.parameters.get('ctl_endpoint', None)
    pass

def collect_events(helper, ew):
    """Implement your data collection logic here """

    opt_log_url = helper.get_arg('log_url')
    proxy = helper.get_proxy()
 
    if proxy.get('proxy_url', False):
        helper.log_debug(proxy)
        os.environ["HTTP_PROXY"] = "http://%s:%s" % (proxy['proxy_url'], proxy['proxy_port'])
        os.environ["HTTPS_PROXY"] = "https://%s:%s" % (proxy['proxy_url'], proxy['proxy_port'])

    log_level = helper.get_log_level()
    helper.set_log_level(log_level)

    helper.get_input_type()

    obj = CTL2Splunk(helper, ew, opt_log_url)
    obj.process_log()   
