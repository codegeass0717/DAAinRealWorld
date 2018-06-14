import sys
sys.path.append('../EPID')
from Module import *
import os

class Group:
	def __init__(self, name):
		self.name = name
		self.path = 'groups/' + name
		self.pubKeyFile = os.path.join(self.path, name + '.pubkey')
		self.prvKeyFile = os.path.join(self.path, name + '.prvkey')
		self.memKeyFile = os.path.join(self.path, name + '.memkey')
		self.bsnFile = os.path.join(self.path, 'bsn')
		with open(self.bsnFile, 'r') as f:
			self.bsnStr = f.read()

class Service:
	def __init__(self, bsn, gid):
		self.bsn = bsn
		self.gid = gid
