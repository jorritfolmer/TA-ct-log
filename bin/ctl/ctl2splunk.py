from future import standard_library
standard_library.install_aliases()
from builtins import str
from builtins import range
from past.builtins import basestring
from builtins import object
import struct
import base64
import json
import requests
import binascii
from asn1crypto.core import Sequence
from urllib.parse import quote
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

class CTL2Splunk(object):
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

    def get_proxies(self):
        proxy = self.helper.get_proxy()
        proxies = {}
        if proxy.get('proxy_url', False):
            if(proxy["proxy_username"] and proxy["proxy_password"]):
                proxy_url = "%s://%s:%s@%s:%s" % (proxy["proxy_type"], proxy["proxy_username"], proxy["proxy_password"], proxy["proxy_url"], proxy["proxy_port"])
                proxies = {
                    "http" : proxy_url,
                    "https" : proxy_url
                }
            else:
                proxy_url = "%s://%s:%s" % (proxy["proxy_type"], proxy["proxy_url"], proxy["proxy_port"])
                proxies = {
                    "http" : proxy_url,
                    "https" : proxy_url
                }
        self.helper.log_debug("proxies dict is : {}".format(proxies))
        return proxies


    def fix_string_encoding(self, s):
        result = ''
        if s:
            encodings = ['utf-8', 'windows-1252', 'latin-1', 'utf16']
            success = 0
            for e in encodings:
                try:
                    result = s.decode(e).encode('utf-8')
                except Exception as e:
                    pass
                else:
                    success = 1
                    break
            if success == 0:
                self.helper.log_warning("fix_string_encoding: unable to decode string with %s: %s" % (encodings,s))
        return result

    def decode_leaf(self, leaf, counter):
        """ Decodes a given raw leaf entry 
            and returns a hash with leaf and leaf certificate metadata """
        leaf_out = dict()
        format = ">BBQHBBB%ds" % (len(base64.b64decode(leaf))-15)
        try:
            version,merkleleaftype,timestamp,logentrytype,s3,s2,s1,entry=struct.unpack(format,base64.b64decode(leaf))
        except Exception as e:
            self.helper.log_warning("decode_leaf: unpack of entry %d failed with %s" % (counter, str(e)))
        else:
            leaf_out['LeafIndex'] = counter
            leaf_out['Timestamp'] = timestamp
            leaf_out['LogEntryType'] = logentrytype
            if logentrytype == 0:
                 size = s1+(s2*256)+(s3*65536)
                 if size > len(base64.b64decode(leaf))-15:
                     self.helper.log_warning("decode_leaf: declared size of leaf cert (%d) is larger than the actual leaf certificate (%d)" % (size, len(base64.b64decode(leaf))-15))
                 else:
                     der = entry[0:size]
                     leaf_out['LeafCertificate'] = self.decode_x509(der, counter)
            else:
                 self.helper.log_debug("decode_leaf: ignoring unsupported entry_type %d" % logentrytype)
        return leaf_out

    def decode_subjectaltname(self, data, counter):
        """ Decodes given ASN1 encoded subjectaltname data
            and returns an array of url strings """
        result = []
        parsed = Sequence.load(data)
        for i in range(0,len(parsed)):
            subjectaltname = parsed[i].native
            if isinstance(subjectaltname, int) or isinstance(subjectaltname, long):
                try:
                    subjectaltname =  binascii.unhexlify('%x' % subjectaltname)
                except TypeError:
                    subjectaltname = subjectaltname
            elif isinstance(subjectaltname, basestring):
                subjectaltname = subjectaltname
            else:
                self.helper.log_warning("decode_subjectaltname: Unknown instance type %s found in entry %d. ASN1 data for debugging: %s" % (type(subjectaltname), counter, binascii.hexlify(data)))
                subjectaltname = ''
            subjectaltname_utf8 = self.fix_string_encoding(subjectaltname)
            if len(subjectaltname_utf8)>0:
                result.append(subjectaltname_utf8)
        return result
 
    def decode_x509(self, der, counter):
        """ Decodes a given certificate 
            and returns a hash with certificate metadata """
        cert = dict()
        try:
            x509=load_certificate(FILETYPE_ASN1, der)
        except Exception as e:
            self.helper.log_warning("decode_x509: exception in entry %d: %s" % (counter, str(e)))
        else:
            cert['issuer'] = ''
            cert['subject'] = ''
            for key,value in x509.get_issuer().get_components():
                cert['issuer'] += "%s=%s, " %(key, value)
            cert['issuer'] = self.fix_string_encoding(cert['issuer'][:-2])
            for key,value in x509.get_subject().get_components():
                cert['subject'] += "%s=%s, " %(key, value)
            cert['subject'] = self.fix_string_encoding(cert['subject'][:-2])
            cert['serial'] = ':'.join(["%02x" % (x509.get_serial_number() >> i & 0xff) for i in (152, 144, 136, 128, 120, 112, 104, 96, 88, 80, 72, 64, 56, 48, 40, 32, 24, 16, 8, 0)])
            cert['validity'] = dict()
            cert['validity']['notafter'] = datetime.strptime(x509.get_notAfter(),"%Y%m%d%H%M%SZ").isoformat(" ") + "+00:00"
            cert['validity']['notbefore'] = datetime.strptime(x509.get_notBefore(),"%Y%m%d%H%M%SZ").isoformat(" ") + "+00:00"
            cert['public_key'] = dict()
            cert['public_key']['bits'] = x509.get_pubkey().bits()
            cert['public_key']['type'] = x509.get_pubkey().type()
            cert['signature_algorithm'] = x509.get_signature_algorithm()
            cert['version'] = x509.get_version()
            cert['x509_extensions'] = dict()
            try:
                for i in range(0,x509.get_extension_count()):
                    name = x509.get_extension(i).get_short_name()
                    if name == 'subjectAltName':
                        data = x509.get_extension(i).get_data()
                        subjectaltname = self.decode_subjectaltname(data, counter)
                        cert['x509_extensions'][name] = subjectaltname
            except Exception as e:
                self.helper.log_warning("decode_x509 in extension retrieval of entry %d: %s" % (counter, str(e)))
        return cert

    def get_entries(self, start, end):
        """ Fetches entries from the log
            and returns an array of raw leaf_inputs
            (extra_data is currently ignored) """
        leafs = []
        try:
            r = requests.get('https://{}ct/v1/get-entries?start={}&end={}'.format(self.log_url,start,end), timeout=20, proxies=self.get_proxies())
        except Exception as e:
            self.helper.log_error("get_entries: exception getting %s: %s" % (self.log_url, str(e)))
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
            r = requests.get('https://{}ct/v1/get-sth'.format(self.log_url), timeout=10, proxies=self.get_proxies())
	except Exception as e:
            self.helper.log_error("get_tree_size(): %s exception %s" %  (self.log_url, str(e)))
            return False
        else:
            if r.status_code == 200:
                try:
                    sth = json.loads(r.text)
                except ValueError as e:
                    self.helper.log_warning("get_tree_size(): Invalid JSON received")
                    return False
                else:
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
            if tree_size % 50 == 0:
                # For performance reasons, only save a checkpoint every 50 entries
                self.helper.save_check_point(quote(self.log_url, safe=''), tree_size)
        except Exception as e:
            raise Exception("Error saving checkpoint data with with exception %s" % str(e))

    def process_log(self):
        """ For the given log_url instance variable
            process the MerkleTreeLeaves 
            into Splunk events """
        # TODO: determine fetch_size for a given log_url
        # A fetch_size of 64 is barely enough to keep up with argon2018
        fetch_size = 256
        tree_size = self.get_tree_size()
	if tree_size>0:
            try:
                previous_tree_size = self.helper.get_check_point(quote(self.log_url,safe=''))
            except Exception as e:
                self.helper.log_debug("process_log: get_check_point for %s failed with %s" % (self.log_url, str(e)))
                previous_tree_size = tree_size - 64
            previous_tree_size = (tree_size - 64) if previous_tree_size == None else previous_tree_size
            self.helper.log_info("process_log: starting %s tree_size: %d, previous_tree_size: %d" % (self.log_url, tree_size, previous_tree_size))
            if tree_size == previous_tree_size:
                self.helper.log_info("process_log: no new ct logs at %s" % self.log_url)
            counter = previous_tree_size
            for i in range(previous_tree_size, tree_size, fetch_size):
                leaf_inputs = self.get_entries(i, i+fetch_size-1)
                counter = i
                for leaf in leaf_inputs:
                     leaf = self.decode_leaf(leaf, counter)
                     if len(leaf)>0:
                         try:
                             self.leaf2splunk(json.dumps(leaf), counter)
                         except Exception as e:
                             self.helper.log_warning("process_log: exception at entry %d of %s: %s" % (counter, self.log_url, str(e)))
                     counter=counter+1
            try:
                # Make sure we checkpoint the final tree index, because we might miss checkpoints because of the 1-in-50 checkpoint in leaf2splunk
                self.helper.save_check_point(quote(self.log_url, safe=''), counter)
            except Exception as e:
                raise Exception("Error saving checkpoint data with with exception %s" % str(e))
            self.helper.log_info("process_log: finished %s at %d" % (self.log_url, counter))
        else:
            self.helper.log_debug("process_log: finished without processing entries because tree_size was %s" % tree_size)
