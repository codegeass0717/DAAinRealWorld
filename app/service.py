import sys
sys.path.append('../EPID')
from Module import *
import os

class Service:
    def __init__(self, name, path, memkey = None):
        self.name = name
        self.path = path
        self.pubKeyFile = os.path.join(path, name + '.pubkey')
        self.prvKeyFile = os.path.join(path, name + '.prvkey')
        self.memKeyFile = os.path.join(path, name + '.memkey')
        self.bsnFile = os.path.join(path, 'bsn')
        with open(self.bsnFile, 'r') as f:
            self.bsnStr = f.read()

        self.issuer = Issuer()
        self.issuer.load(self.prvKeyFile, bsnFile=self.bsnFile)

        self.verifier = Member()
        if memkey == None:
		    self.verifier.load(self.pubKeyFile, None, bsnFile=self.bsnFile)
        else:
		    self.verifier.load(self.pubKeyFile, self.memKeyFile, bsnFile=self.bsnFile)
