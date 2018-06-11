import sys
sys.path.append('../EPID')
from Module import *
import os

class Service:
	def __init__(self, name, path):
		self.name = name
		self.path = path
		self.pubKeyFile = os.path.join(path, name + '.pubkey')
		self.prvKeyFile = os.path.join(path, name + '.prvkey')
		self.bsnFile = os.path.join(path, 'bsn')
		with open(self.bsnFile, 'r') as f:
			self.bsnStr = f.read()

		self.issuer = Issuer()
		self.issuer.load(self.prvKeyFile, bsnFile=self.bsnFile)

		self.verifier = Member()
		self.verifier.load(self.pubKeyFile, None, bsnFile=self.bsnFile)