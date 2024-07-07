# Copyright (c) (2018-2020) Apple Inc. All rights reserved.
#
# corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
# is contained in the License.txt file distributed with corecrypto) and only to
# people who accept that license. IMPORTANT:  Any license rights granted to you by
# Apple Inc. (if any) are limited to internal use within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software.  You may
# not, directly or indirectly, redistribute the Apple Software or any portions thereof.

from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

def ConvertStringToPrintableHex (str):
    output = ''.join(x.encode('hex') for x in str)
    return "\""+output+"\""

def ConvertStringToPrintableHexString (str):
    output = '\\x'.join(x.encode('hex') for x in str)
    return "\"\\x"+output+"\""


adata = b'This is a test'
pdata = b'plaintext data goes here'
key = b'0123456789012345'
nonce = b'2109876543210'
mac_length=12
message_length=24
adata_repeat=5000

cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=mac_length, msg_len=message_length, assoc_len=adata_repeat*len(adata))
for x in range (0, adata_repeat):
    cipher.update(adata)
ciphertext = cipher.encrypt (pdata)
tag = cipher.digest()
msg = (nonce, adata, ciphertext , tag)
print msg
print type(nonce)
print type(adata)
print type(ciphertext)
print type(tag)
print "{"
print "\t.key = " + ConvertStringToPrintableHex(key) + ","
print "\t.nonce = " + ConvertStringToPrintableHex(nonce) + ","
print "\t.adata = " + ConvertStringToPrintableHex(adata) + ","
print "\t.adata_repeat = " + str(adata_repeat) + ","
print "\t.pdata = " + ConvertStringToPrintableHex(pdata) + ","
print "\t.tag_length = " + str(mac_length) + ","
print "\t.ciphertext = " + ConvertStringToPrintableHex(ciphertext+tag) + ","
print "\t.solo_ciphertext = " + ConvertStringToPrintableHex(ciphertext) + ","
print "\t.solot_tag = " + ConvertStringToPrintableHex(tag) + ","
print "}"

print "{"
print "\t" + str(len(key))+ "," + ConvertStringToPrintableHexString(key) + ", // Key"
print "\t" + str(len(nonce)) + "," + ConvertStringToPrintableHexString(nonce) + ", // Nonce"
print "\t" + str(len(adata)) + "," + ConvertStringToPrintableHexString(adata) + ", // aData"
print str(adata_repeat) + ", //aData Repeat Factor (ie, number of times to concatenate above string)"
print "\t" + str(len(pdata)) + "," + ConvertStringToPrintableHexString(pdata) + ", // pData"
print str(mac_length) + ", // Tag length"
print "\t" + str(len(ciphertext + tag)) + "," + ConvertStringToPrintableHexString(ciphertext + tag) + ", // Ciphertext and Tag"
print "\t" + str(len(ciphertext)) + "," + ConvertStringToPrintableHexString(ciphertext) + ", // Ciphertext"
print "\t" + str(len(tag)) + "," + ConvertStringToPrintableHexString(tag) + ", // Tag"
print "}"



dec_cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=mac_length, assoc_len=adata_repeat*len(adata))
for x in range (0,adata_repeat-1):
    dec_cipher.update(adata)
dec_cipher.update("This is a test")
plaintext_prime=dec_cipher.decrypt_and_verify (ciphertext=ciphertext, received_mac_tag=tag)
print "decrypted plaintext:" + plaintext_prime


