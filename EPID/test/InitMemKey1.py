import sys
sys.path.append('../../EPID')

from Module import *
import argparse

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-g', metavar='gpubkey', help='file containing group public key', required=True)

	group_bsn = parser.add_mutually_exclusive_group(required=True)
	group_bsn.add_argument('-b', metavar='bsnfile', help='file containing basename')
	group_bsn.add_argument('--bsn', metavar='BASENAME', help='basename string')
	
	parser.add_argument('-s', metavar='secret', help='file containing member secret', required=True)
	parser.add_argument('-o', metavar='output', help='write join request to file', required=True)
	args = parser.parse_args()

	pubKey = publicKey(args.g)

	if args.b:
		with open(args.b, "r") as f:
			bsn = f.readline()
	else:
		bsn = args.bsn

	bsnPower = bsnPow( bsn, pubKey.pGroup, pubKey.qGroup)
	secret   = number.getRandomRange(0, pubKey.qGroup-1)
	vPerp    = number.getRandomInteger(nBit + phiBit)

	K = safePow( bsnPower, secret, pubKey.pGroup)
	U1 = safePow( pubKey.R, secret, pubKey.RSAN)
	U2 = safePow( pubKey.S, vPerp ,pubKey.RSAN) 
	U = (U1*U2) % pubKey.RSAN

	f = open(args.s, "w")
	writeline(f,secret)
	writeline(f,vPerp)
	f.close()

	f = open(args.o, "w")
	writeline(f,K)
	writeline(f,U)
	f.close()

