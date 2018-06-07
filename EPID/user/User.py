from Crypto.Util import number
from Crypto.Hash import SHA256
import sys
sys.path.append("../Module")
from common import *

pubKeyfileName = raw_input("pubkey : ")
memKeyfileName = raw_input("memkey : ")
bsnfileName = raw_input("bsn : ")
msgfileName = raw_input("msg : ")

pubKey = publicKey(pubKeyfileName)
memKey = memberKey(memKeyfileName)

f = open(bsnfileName, "r")
bsn = f.readline()
f.close()

f = open(msgfileName, "r")
msg = f.readline()
f.close()

C1 = sign1( pubKey, memKey, bsn, msg)
C1.write("TestData/sign")
if ( C1.verify( pubKey, bsn, msg)):
    print("success!!")
else:
    print("GodDamn")
