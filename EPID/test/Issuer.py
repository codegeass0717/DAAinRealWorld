import sys
sys.path.append('../../EPID')

from Module import *
import argparse

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

class Issuer():
	def generate_key(self, privkey, bsn, join, output):
		prvKey = privateKey(privkey)
		bsnPower = bsnPow( bsn, prvKey.pGroup, prvKey.qGroup)

		f = open(join, "r")
		K = int(f.readline())
		U = int(f.readline())
		f.close()

		(A,e,v) = createMemKey(K, U, prvKey)
		f = open(output, "w")
		writeline(f, str(A))
		writeline(f, str(e))
		writeline(f, str(v))
		f.close()
		

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-p', metavar='privkey', help='file containing issuer private key', required=True)

	group_bsn = parser.add_mutually_exclusive_group(required=True)
	group_bsn.add_argument('-b', metavar='bsnfile', help='file containing basename')
	group_bsn.add_argument('--bsn', metavar='BASENAME', help='basename string')
	
	parser.add_argument('-j', metavar='join', help='file containing join request', required=True)
	parser.add_argument('-o', metavar='output', help='write temp member private key to file', required=True)
	args = parser.parse_args()


	prvKey = privateKey(args.p)
	if args.b:
		with open(args.b, "r") as f:
			bsn = f.readline()
	else:
		bsn = args.bsn

	bsnPower = bsnPow( bsn, prvKey.pGroup, prvKey.qGroup)

	f = open(args.j, "r")
	K = int(f.readline())
	U = int(f.readline())
	f.close()

	f = open(args.o, "w")
	(A,e,v) = createMemKey( K, U, prvKey)
	writeline(f, str(A))
	writeline(f, str(e))
	writeline(f, str(v))
	f.close()
