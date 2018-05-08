# Standalone script to test precert decoding

import struct
import base64
import json
import requests
import binascii
from urllib import quote
from OpenSSL.crypto import load_certificate,FILETYPE_ASN1
from datetime import datetime

def decode_leaf(leaf, counter):
    """ Decodes a given raw leaf entry 
        and returns a hash with leaf and leaf certificate metadata """
    leaf_out = dict()
    format = ">BBQH%ds" % (len(base64.b64decode(leaf))-12)
    try:
        version,merkleleaftype,timestamp,logentrytype,entry=struct.unpack(format,base64.b64decode(leaf))
    except Exception, e:
        print("decode_leaf: unpack failed with %s" % str(e))
    else:
        leaf_out['LeafIndex'] = counter
        leaf_out['Timestamp'] = timestamp
        leaf_out['LogEntryType'] = logentrytype
        if logentrytype == 0:
            format = ">BBB%ds" % (len(base64.b64decode(leaf))-3)
            s3,s2,s1,entry = struct.unpack(format,entry)
            size = s1+(s2*256)+(s3*65536)
            if size > len(base64.b64decode(leaf))-15:
                print("decode_leaf: declared size of leaf cert (%d) is larger than the actual leaf certificate (%d)" % (size, len(base64.b64decode(leaf))-15))
            else:
                der = entry[0:size]
                leaf_out['LeafCertificate'] = decode_x509(der)
        elif logentrytype == 1:
            format = ">32s4s%ds" % (len(entry)-36)
            try:
                issuer_key_hash,gunk,tbs_certificate=struct.unpack(format,entry)
            except Exception, e:
                print("decode_leaf: unpack failed with %s" % str(e))
            else:
                leaf_out['issuer_key_hash'] = binascii.hexlify(issuer_key_hash)
                leaf_out['LeafCertificate'] = decode_x509(tbs_certificate)
        else:
             print("decode_leaf: ignoring unsupported entry_type %d" % logentrytype)
    return leaf_out

def decode_x509(der):
    """ Decodes a given certificate 
        and returns a hash with certificate metadata """
    cert = dict()
    try:
        x509=load_certificate(FILETYPE_ASN1, der)
    except Exception, e:
        print("decode_x509: %s" % str(e))
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


decode_leaf('AAAAAAFjO8zZ6gABwUY9EOTJmS7Aj4fDVCu/KeE++mV7FgIcbn4WhMz1I2kABNwwggTYoAMCAQICExYAAaWwu6IgXpMFZxAAAAABpbAwDQYJKoZIhvcNAQELBQAwgYsxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xFTATBgNVBAsTDE1pY3Jvc29mdCBJVDEeMBwGA1UEAxMVTWljcm9zb2Z0IElUIFRMUyBDQSA0MB4XDTE4MDUwNzE4MDEwM1oXDTIwMDUwNzE4MDEwM1owOjE4MDYGA1UEAxMvZGlpZmVlZGJhY2tzZi1wcm9kLmNlbnRyYWx1cy5jbG91ZGFwcC5henVyZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDoiv3nNq9Q0EXSpzJjyxPdlJMj0EmqmhmiNdDSrd/9tbeH3T4rnefLpkjkXz+K4E/0wkLcr3Laxr+GDCZ5LksKnPTcyo7HuEgYk1uRxekMjq1A09UjZDnVRiETUPb8D3zNRIJ5er9uBQCXFZuaO2II0BaEO4dYYmqO3AfKTbPmr/yghDn5sLUAHcNEnWNm3hPsvmSKbEhbhhQrdKAtX13l9lt6ER+hRQ1LwcJkVrlm2IiucY610KS8Dv+BTYxdRvg2dcGVTsFIJu/T6+4b3JG1TftjjuqH2j8pQX/B6R/gev8BEuw6FjchtkE45OGk0bDRU05bsztOQTIMB6pvMaf5AgMBAAGjggKbMIIClzAnBgkrBgEEAYI3FQoEGjAYMAoGCCsGAQUFBwMCMAoGCCsGAQUFBwMBMD4GCSsGAQQBgjcVBwQxMC8GJysGAQQBgjcVCIfahnWD7tkBgsmFG4G1nmGF9OtggV2E0t9CgueTegIBZAIBHTCBhQYIKwYBBQUHAQEEeTB3MFEGCCsGAQUFBzAChkVodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpL21zY29ycC9NaWNyb3NvZnQlMjBJVCUyMFRMUyUyMENBJTIwNC5jcnQwIgYIKwYBBQUHMAGGFmh0dHA6Ly9vY3NwLm1zb2NzcC5jb20wHQYDVR0OBBYEFK+M+Zk8rlLJHnu6pKQXmWslwoS4MAsGA1UdDwQEAwIEsDA6BgNVHREEMzAxgi9kaWlmZWVkYmFja3NmLXByb2QuY2VudHJhbHVzLmNsb3VkYXBwLmF6dXJlLmNvbTCBrAYDVR0fBIGkMIGhMIGeoIGboIGYhktodHRwOi8vbXNjcmwubWljcm9zb2Z0LmNvbS9wa2kvbXNjb3JwL2NybC9NaWNyb3NvZnQlMjBJVCUyMFRMUyUyMENBJTIwNC5jcmyGSWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvbXNjb3JwL2NybC9NaWNyb3NvZnQlMjBJVCUyMFRMUyUyMENBJTIwNC5jcmwwTQYDVR0gBEYwRDBCBgkrBgEEAYI3KgEwNTAzBggrBgEFBQcCARYnaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL3BraS9tc2NvcnAvY3BzMB8GA1UdIwQYMBaAFHp7jMHP56DKHNRr+vvhM8MPGqKdMB0GA1UdJQQWMBQGCCsGAQUFBwMCBggrBgEFBQcDAQAA', 123456)

