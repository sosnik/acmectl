#!/usr/bin/python
# convert JWK private key (used by certbot) to PEM key (used by acme_tiny/acme_hooked)
# source: https://gist.githubusercontent.com/JonLundy/f25c99ee0770e19dc595/raw/6035c1c8938fae85810de6aad1ecf6e2db663e26/conv.py

# usage:
#	# Create a DER encoded private key
#	openssl asn1parse -noout -out private_key.der -genconf <(python2 conv.py private_key.json)
#
#	# Convert to PEM
#	openssl rsa -in private_key.der -inform der > account.key

import sys,json,base64,binascii
with open(sys.argv[1]) as fp:
    pkey=json.load(fp)

def enc(data):
    missing_padding = 4 - len(data) % 4
    if missing_padding:
      data += b'='* missing_padding
    return '0x'+binascii.hexlify(base64.b64decode(data,b'-_')).upper()

for k,v in pkey.items(): 
    if k == 'kty': continue 
    pkey[k] = enc(v.encode())

print "asn1=SEQUENCE:private_key\n[private_key]\nversion=INTEGER:0"
print "n=INTEGER:{}".format(pkey[u'n'])
print "e=INTEGER:{}".format(pkey[u'e'])
print "d=INTEGER:{}".format(pkey[u'd'])
print "p=INTEGER:{}".format(pkey[u'p'])
print "q=INTEGER:{}".format(pkey[u'q'])
print "dp=INTEGER:{}".format(pkey[u'dp'])
print "dq=INTEGER:{}".format(pkey[u'dq'])
print "qi=INTEGER:{}".format(pkey[u'qi'])
