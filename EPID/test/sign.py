import sys
sys.path.append('../../EPID')

from Module import *
import argparse

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-g', metavar='gpubkey', help='file containing group public key', required=True)
	parser.add_argument('-p', metavar='mprivkey', help='file containing member private key', required=True)

	group_bsn = parser.add_mutually_exclusive_group(required=True)
	group_bsn.add_argument('-b', metavar='bsnfile', help='file containing basename')
	group_bsn.add_argument('--bsn', metavar='BASENAME', help='basename string')

	group_msg = parser.add_mutually_exclusive_group(required=True)
	group_msg.add_argument('-m', metavar='msgfile', help='file containing message to sign')
	group_msg.add_argument('--msg', metavar='MESSAGE', help='message string')
	
	parser.add_argument('-o', metavar='output', help='write signature to file', required=True)
	args = parser.parse_args()

	pubKey = publicKey(args.g)
	memKey = memberKey(args.p)

	if args.b:
		with open(args.b, "r") as f:
			bsn = f.readline()
	else:
		bsn = args.bsn

	if args.m:
		with open(args.m, "r") as f:
			msg = f.readline()
	else:
		msg = args.msg

	C1 = sign1(pubKey, memKey, bsn, msg)
	C1.write(args.o)
	
	print("success!!")