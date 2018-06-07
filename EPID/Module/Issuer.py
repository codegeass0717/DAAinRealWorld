from common import *
import KeyGenerator
import Issuer_core

class Issuer:
	def generate_keys(self, filename):
		KeyGenerator.setup(filename)

	def generate_tmpmemkey(self, prvKey, bsnFile, joinFile, memFile):
		prvKey = privateKey(prvKey)

		f = open(bsnFile, "r")
		bsn = f.readline().strip()
		f.close()

		bsnPower = bsnPow( bsn, prvKey.pGroup, prvKey.qGroup)

		f = open(joinFile, "r")
		K = int(f.readline())
		U = int(f.readline())
		f.close()

		f = open(memFile, "w")
		(A,e,v) = Issuer_core.createMemKey( K, U, prvKey)
		writeline(f, str(A))
		writeline(f, str(e))
		writeline(f, str(v))
		f.close()