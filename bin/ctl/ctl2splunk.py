import struct
import base64
import json
import requests
from urllib import quote
from OpenSSL.crypto import load_certificate,FILETYPE_ASN1
from datetime import datetime

# Copyright 2018 Jorrit Folmer
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

class CTL2Splunk:
    """ This class:
        - gets Certificate Transparency Logs from a given log url
        - decodes the certificates in the MerkleTreeLeafs
        - and saves the certificate metadata as events to Splunk """

    def __init__(self, helper, ew, log_url):
        # Instance variables:
        self.helper    = helper
        self.log_url   = log_url if log_url[-1]=='/' else "{}/".format(log_url)
        self.ew        = ew
        self.tree_size = 0

    def decode_leaf(self, leaf):
        """ Decodes a given raw leaf entry 
            and returns a hash with leaf and leaf certificate metadata """
        leaf_cert = dict()
        format = ">BBQHBBB%ds" % (len(base64.b64decode(leaf))-15)
        try:
            version,merkleleaftype,timestamp,logentrytype,s3,s2,s1,entry=struct.unpack(format,base64.b64decode(leaf))
        except Exception, e:
            self.helper.log_warning("decode_leaf: unpack failed with %s" % str(e))
        else:
            leaf_cert['Timestamp'] = timestamp
            leaf_cert['LogEntryType'] = logentrytype
            if logentrytype == 0:
                 size = s1+(s2*256)+(s3*65536)
                 if size > len(base64.b64decode(leaf))-15:
                     self.helper.log_warning("decode_leaf: declared size of leaf cert (%d) is larger than the actual leaf certificate (%d)" % (size, len(base64.b64decode(leaf))-15))
                 else:
                     der = entry[0:size]
                     leaf_cert['LeafCertificate'] = self.decode_x509(der)
            else:
                 self.helper.log_debug("decode_leaf: ignoring unsupported entry_type %d" % logentrytype)
        return leaf_cert

    def decode_x509(self, der):
        """ Decodes a given certificate 
            and returns a hash with certificate metadata """
        cert = dict()
        try:
            x509=load_certificate(FILETYPE_ASN1, der)
        except Exception, e:
            self.helper.log_warning("decode_x509: %s", str(e))
        else:
            cert['issuer'] = ''
            cert['subject'] = ''
            for key,value in x509.get_issuer().get_components():
                cert['issuer'] += "%s=%s, " %(key, value)
            cert['issuer'] = cert['issuer'][:-2]
            for key,value in x509.get_subject().get_components():
                cert['subject'] += "%s=%s, " %(key, value)
            cert['subject'] = cert['subject'][:-2]
            cert['serial'] = ':'.join(["%02x" % (x509.get_serial_number() >> i & 0xff) for i in (152, 144, 136, 128, 120, 112, 104, 96, 88, 80, 72, 64, 56, 48, 40, 32, 24, 16, 8, 0)])
            cert['validity'] = dict()
            cert['validity']['notafter'] = datetime.strptime(x509.get_notAfter(),"%Y%m%d%H%M%SZ").isoformat(" ") + "+00:00"
            cert['validity']['notbefore'] = datetime.strptime(x509.get_notBefore(),"%Y%m%d%H%M%SZ").isoformat(" ") + "+00:00"
            cert['public_key'] = dict()
            cert['public_key']['bits'] = x509.get_pubkey().bits()
            cert['public_key']['type'] = x509.get_pubkey().type()
            cert['signature_algorithm'] = x509.get_signature_algorithm()
            cert['version'] = x509.get_version()
        return cert

    def get_entries(self, start, end):
        """ Fetches entries from the log
            and returns an array of raw leaf_inputs
            (extra_data is currently ignored) """
        leafs = []
        try:
            r = requests.get('https://{}ct/v1/get-entries?start={}&end={}'.format(self.log_url,start,end), timeout=20)
        except Exception, e:
            self.helper.log_error("get_entries: %s, status %s, %s" %  (r.url, r.status_code, str(e)))
        else:
            if r.status_code == 200:
                self.helper.log_debug("get_entries: %s, status %s" %  (r.url, r.status_code))
                log = json.loads(r.text)
                for leaf in log['entries']:
                    leafs.append(leaf['leaf_input'])
            else:
                self.helper.log_warning("get_entries: %s, status %s" %  (r.url, r.status_code))
            return leafs

    def get_tree_size(self):
        """ Fetches the current tree_size from the given log_url instance variable
            and returns the size as an integer """
	try:
            r = requests.get('https://{}ct/v1/get-sth'.format(self.log_url), timeout=10)
	except Exception, e:
            raise Exception("Error connecting to https://%sct/v1/get-sth with %s" % (self.log_url, str(e))) 
        else:
            if r.status_code == 200:
                sth = json.loads(r.text)
                return sth['tree_size']
            else:
                self.helper.log_warning("get_tree_size(): %s, http status %s" %  (r.url, r.status_code))
                return False

    def leaf2splunk(self, leaf, tree_size):
        """ For the given leaf
            push an event to splunk
            and update the previous_tree_size for the log_url """

        try:
            event = self.helper.new_event(leaf, time=None, host=None, index=self.helper.get_output_index(),
                                          source=self.log_url, sourcetype=self.helper.get_sourcetype(),
                                          done=True, unbroken=True)
            self.ew.write_event(event)
        except Exception as e:
            raise Exception("Exception in write_event(): %s" % e)

        try:
            self.helper.save_check_point(quote(self.log_url, safe=''), tree_size)
        except Exception as e:
            raise Exception("Error saving checkpoint data with with exception %s" % str(e))

    def process_log(self):
        """ For the given log_url instance variable
            process the MerkleTreeLeaves 
            into Splunk events """
        fetch_size = 64
        tree_size = self.get_tree_size()
        try:
            previous_tree_size = self.helper.get_check_point(quote(self.log_url,safe=''))
        except Exception, e:
            self.helper.log_debug("process_log: get_check_point for %s failed with %s" % (self.log_url, str(e)))
            previous_tree_size = tree_size - 64
        previous_tree_size = (tree_size - 64) if previous_tree_size == None else previous_tree_size
        self.helper.log_info("process_log: starting %s tree_size: %d, previous_tree_size: %d" % (self.log_url, tree_size, previous_tree_size))
        if tree_size == previous_tree_size:
            self.helper.log_info("process_log: no new ct logs at %s" % self.log_url)
        counter = previous_tree_size
        for i in range(previous_tree_size, tree_size, fetch_size):
            leaf_inputs = self.get_entries(i, i+fetch_size)
            counter = i
            for leaf in leaf_inputs:
                 leaf = self.decode_leaf(leaf)
                 counter=counter+1
                 if len(leaf)>0:
                     self.leaf2splunk(json.dumps(leaf), counter)
        self.helper.log_info("process_log: finished %s at %d" % (self.log_url, counter))
