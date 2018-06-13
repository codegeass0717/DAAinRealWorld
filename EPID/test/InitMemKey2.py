import sys
sys.path.append('../../EPID')

from Module import *
import argparse

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument('-t', metavar='tmpmemkey', help='file containing temp member key', required=True)
	parser.add_argument('-s', metavar='secret', help='file containing member secret', required=True)
	parser.add_argument('-o', metavar='output', help='write member key to file', required=True)
	args = parser.parse_args()

	memKey = memberKey()
	memKey.mix(args.t, args.s)
	memKey.write(args.o)