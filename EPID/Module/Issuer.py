from common import *
import KeyGenerator
import Issuer_core

class Issuer:
	def generate_keys(self, filename):
		KeyGenerator.setup(filename)

	def load(self, prvKeyFile, bsnFile=None, bsnStr=None):
		self.prvKey = privateKey(prvKeyFile)

		if bsnFile:
			with open(bsnFile, "r") as f:
				self.bsn = f.readline().strip()
		else:
			self.bsn = bsnStr

	def generate_tmpmemkey(self, joinFile, memFile):
		bsnPower = bsnPow(self.bsn, self.prvKey.pGroup, self.prvKey.qGroup)

		f = open(joinFile, "r")
		K = int(f.readline())
		U = int(f.readline())
		f.close()

		f = open(memFile, "w")
		(A,e,v) = Issuer_core.createMemKey( K, U, self.prvKey)
		writeline(f, str(A))
		writeline(f, str(e))
		writeline(f, str(v))
		f.close()