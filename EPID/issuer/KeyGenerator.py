from Crypto.Util import number
import sys
sys.path.append("../Module")
from common import *
def createPrimeOrderGroup(pPrime, qPrime, MOD):
    while(1):   
        q = number.getPrime(qGroupBit)
        r = 0
        for i in range(10000000):
            r = number.getRandomNBitInteger(pGroupBit-qGroupBit)
            p = (r*q+1) % MOD
            if(number.isPrime(p)):
                u = number.getRandomInteger(nBit)
                u1 = safePow(u,p-1,MOD)
                qInv = number.inverse( q, (pPrime-1)*(qPrime-1))
                u2 = safePow(u1,qInv,MOD)
                if(u2 != 0):
                    return ( q, p, u)


def generatorOfQR(MOD):
    while(1):
        num = number.getRandomInteger(nBit)
        tmp = num**2
        if(number.GCD( tmp+1, MOD) and number.GCD(tmp-1, MOD)):
            return tmp

def setup(fileName):
    # Create Strong prime and RSA modulus
    pPrime = number.getStrongPrime(1024)
    qPrime = number.getStrongPrime(1024)
    p = (pPrime-1)/ 2
    q = (qPrime-1)/ 2
    RSAn   = p*q
    RSAN   = pPrime * qPrime
    
    # Choose a generator of QR
    gPerp = generatorOfQR(RSAN)

    # Create Public Key
    xG = number.getRandomInteger(1023)
    xH = number.getRandomInteger(1023)
    xS = number.getRandomInteger(1023)
    xZ = number.getRandomInteger(1023)
    xR = number.getRandomInteger(1023)

    G = safePow(gPerp, xG, RSAN)
    H = safePow(gPerp, xH, RSAN)
    S = safePow(H, xS, RSAN)
    Z = safePow(H, xZ, RSAN)
    R = safePow(H, xR, RSAN)

    # Create Prime Order Group
    ( pGroup, qGroup, u) = createPrimeOrderGroup( pPrime, qPrime, RSAN)
    
    pubKey = publicKey()
    pubKey.set( RSAN, gPerp, G, H, S, Z, R, pGroup, qGroup, u)
    prvKey = privateKey()
    prvKey.set( pPrime, qPrime, RSAN, gPerp, G, H, S, Z, R, pGroup, qGroup, u)

    pubKey.write(fileName+".pubkey")
    prvKey.write(fileName+".prvkey")
    
fileName = raw_input("fileName : ")
setup(fileName)
