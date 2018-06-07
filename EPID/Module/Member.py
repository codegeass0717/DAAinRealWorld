from common import *

class Member:
	def init_memkey1(self, pubKeyFile, bsnFile, secretFile, joinFile):
		pubKey = publicKey(pubKeyFile)

		f = open(bsnFile, "r")
		bsn = f.readline().strip()
		f.close()

		bsnPower = bsnPow( bsn, pubKey.pGroup, pubKey.qGroup)
		secret   = number.getRandomRange(0, pubKey.qGroup-1)
		vPerp    = number.getRandomInteger(nBit + phiBit)

		K = safePow( bsnPower, secret, pubKey.pGroup)
		U1 = safePow( pubKey.R, secret, pubKey.RSAN)
		U2 = safePow( pubKey.S, vPerp ,pubKey.RSAN) 
		U = (U1*U2) % pubKey.RSAN

		f = open(secretFile, "w")
		writeline(f,secret)
		writeline(f,vPerp)
		f.close()

		f = open(joinFile, "w")
		writeline(f,K)
		writeline(f,U)
		f.close()

	def init_memkey2(self, tmpMemKeyFile, tmpMemSecertFile, memSecretFile):
		memKey = memberKey()
		memKey.mix(tmpMemKeyFile, tmpMemSecertFile)
		memKey.write(memSecretFile)

	def load(self, pubKeyFile, memKeyFile=None, bsnFile=None, bsnStr=None):
		self.pubKey = publicKey(pubKeyFile)
		if memKeyFile:
			self.memKey = memberKey(memKeyFile)

		if bsnFile:
			with open(bsnFile, "r") as f:
				self.bsn = f.readline().strip()
		else:
			self.bsn = bsnStr

	def sign(self, signFile, msgFile=None, msgStr=None):
		if msgFile:
			with open(msgFile, "r") as f:
				msg = f.readline().strip()
		else:
			msg = msgStr

		C1 = sign1(self.pubKey, self.memKey, self.bsn, msg)
		C1.write(signFile)

	def verify(self, signFile, msgFile=None, msgStr=None):
		if msgFile:
			with open(msgFile, "r") as f:
				msg = f.readline().strip()
		else:
			msg = msgStr

		C1 = sign1()
		C1.readfrom(signFile)
		return C1.verify(self.pubKey, self.bsn, msg)