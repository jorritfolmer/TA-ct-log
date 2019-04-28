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

    log_level = helper.get_log_level()
    helper.set_log_level(log_level)
    opt_log_url = helper.get_arg('log_url')

    obj = CTL2Splunk(helper, ew, opt_log_url)
    obj.process_log()   
