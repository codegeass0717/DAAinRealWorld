from Crypto.Util import number
from Crypto.Hash import SHA256
import sys
sys.path.append("../Module")
from common import *

fileName = raw_input("pubkey :")
pubKey = publicKey(fileName)

fileName = raw_input("bsnFile :")
f = open(fileName, "r")
bsn = f.readline()
f.close()

bsnPower = bsnPow( bsn, pubKey.pGroup, pubKey.qGroup)
secret   = number.getRandomRange(0, pubKey.qGroup-1)
vPerp    = number.getRandomInteger(nBit + phiBit)

K = safePow( bsnPower, secret, pubKey.pGroup)
U1 = safePow( pubKey.R, secret, pubKey.RSAN)
U2 = safePow( pubKey.S, vPerp ,pubKey.RSAN) 
U = (U1*U2) % pubKey.RSAN

filename = raw_input("secret :")
f = open( filename, "w")
writeline(f,secret)
writeline(f,vPerp)
f.close()

filename = raw_input("Join :")
f = open( filename, "w")
writeline(f,K)
writeline(f,U)
f.close()

