from Crypto.Util import number
from Crypto.Hash import SHA256
import sys
sys.path.append("../Module")
from common import *

fileName = raw_input("prvkey : ")
prvKey = privateKey(fileName)

fileName = raw_input("bsnFile: ")
f = open(fileName, "r")
bsn = f.readline()
f.close()

bsnPower = bsnPow( bsn, prvKey.pGroup, prvKey.qGroup)

def createMemKey( K, U, prvKey):
    v = number.getRandomNBitInteger(vBit)
    e = 4
    while(not number.isPrime(e)):
        e = number.getRandomRange( E, EPerp)
    S_v = safePow( prvKey.S, v, prvKey.RSAN)
    A   = prvKey.Z * number.inverse( U * S_v, prvKey.RSAN)
    power = number.inverse( e, (prvKey.pPrime-1)*(prvKey.qPrime-1))
    A   = safePow(A, power, prvKey.RSAN)
    return( A, e, v)

filename = raw_input("Join :")
f = open(filename, "r")
K = int(f.readline())
U = int(f.readline())
f.close()

Mem = raw_input("MemberName :")

f = open(Mem + ".tmpmemkey", "w")
(A,e,v) = createMemKey( K, U, prvKey)
writeline(f, str(A))
writeline(f, str(e))
writeline(f, str(v))
f.close()
