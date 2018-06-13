from Crypto.Util import number
from Crypto.Hash import SHA256

# Some Constant
eBit   = 576
E      = 2**eBit
ePerpBit  = 128
EPerp     = E + 2** ePerpBit
nBit   = 2048
vBit   = 2720
phiBit = 80
rBit   = 80
hBit   = 256
pGroupBit   = 1632
qGroupBit   = 208
secretBit = 208

def writeline(f, number):
    f.write(str(number)+"\n")
    return

class publicKey:
    RSAN = 0
    gPerp = 0
    G = 0
    H = 0
    S = 0
    Z = 0
    R = 0
    pGroup = 0
    qGroup = 0
    u = 0
    def __init__( self, fileName = None):
        if fileName != None:
            f = open(fileName, "r")
            self.RSAN = int(f.readline())
            self.gPerp = int(f.readline())
            self.G = int(f.readline())
            self.H = int(f.readline())
            self.S = int(f.readline())
            self.Z = int(f.readline())
            self.R = int(f.readline())
            self.pGroup = int(f.readline())
            self.qGroup = int(f.readline())
            self.u = int(f.readline())
            f.close()
    def set( self, RSAN, gPerp, G, H, S, Z, R, pGroup, qGroup, u):
        self.RSAN = RSAN
        self.gPerp = gPerp
        self.G = G
        self.H = H
        self.S = S
        self.Z = Z
        self.R = R
        self.pGroup = pGroup
        self.qGroup = qGroup
        self.u = u
    def write( self, fileName):
        f = open(fileName, "w")
        writeline(f, self.RSAN)
        writeline(f, self.gPerp)
        writeline(f, self.G)
        writeline(f, self.H)
        writeline(f, self.S)
        writeline(f, self.Z)
        writeline(f, self.R)
        writeline(f, self.pGroup)
        writeline(f, self.qGroup)
        writeline(f, self.u)
        f.close()

class privateKey:
    pPrime = 0
    qPrime = 0
    RSAN = 0
    gPerp = 0
    G = 0
    H = 0
    S = 0
    Z = 0
    R = 0
    pGroup = 0
    qGroup = 0
    u = 0
    def __init__( self, fileName=None):
        if fileName != None:
            f = open(fileName, "r")
            self.pPrime = int(f.readline())
            self.qPrime = int(f.readline())
            self.RSAN = int(f.readline())
            self.gPerp = int(f.readline())
            self.G = int(f.readline())
            self.H = int(f.readline())
            self.S = int(f.readline())
            self.Z = int(f.readline())
            self.R = int(f.readline())
            self.pGroup = int(f.readline())
            self.qGroup = int(f.readline())
            self.u = int(f.readline())
            f.close()
    def set( self, pPrime, qPrime,  RSAN, gPerp, G, H, S, Z, R, pGroup, qGroup, u):
        self.pPrime = pPrime
        self.qPrime = qPrime
        self.RSAN = RSAN
        self.gPerp = gPerp
        self.G = G
        self.H = H
        self.S = S
        self.Z = Z
        self.R = R
        self.pGroup = pGroup
        self.qGroup = qGroup
        self.u = u
    def write( self, fileName):
        f = open(fileName, "w")
        writeline(f, self.pPrime)
        writeline(f, self.qPrime)
        writeline(f, self.RSAN)
        writeline(f, self.gPerp)
        writeline(f, self.G)
        writeline(f, self.H)
        writeline(f, self.S)
        writeline(f, self.Z)
        writeline(f, self.R)
        writeline(f, self.pGroup)
        writeline(f, self.qGroup)
        writeline(f, self.u)
        f.close()

class memberKey:
    A = 0
    e = 0
    f = 0
    v = 0
    def __init__(self, fileName=None):
        if fileName != None:
            f = open(fileName, "r")
            self.A = int(f.readline())
            self.e = int(f.readline())
            self.f = int(f.readline())
            self.v = int(f.readline())
            f.close()
    def write(self, fileName):
        f = open(fileName, "w")
        writeline(f, self.A)
        writeline(f, self.e)
        writeline(f, self.f)
        writeline(f, self.v)
        f.close()
    def mix(self, fileName1, fileName2):
        f1 = open(fileName1, "r")
        self.A = int(f1.readline())
        self.e = int(f1.readline())
        v = int(f1.readline())
        f1.close()
        f2 = open(fileName2, "r")
        self.f = int(f2.readline())
        v1 = int(f2.readline())
        self.v = v + v1
        f2.close()

class sign1:
    B = 0
    K = 0
    T1 = 0
    T2 = 0
    C1 = 0
    Sv = 0
    Sf = 0
    Se = 0
    Sr = 0
    Sw = 0
    Sew = 0
    See = 0
    Ser = 0
    Sbsn = 0
    def __init__( self, pubKey = None, memKey=None, bsn=None, msg=None):
        if pubKey != None:
            bsnPower = bsnPow( bsn, pubKey.pGroup, pubKey.qGroup)
            msgHash = SHA256.new()
            msgHash.update(msg)

            w = number.getRandomInteger(nBit + phiBit)
            r = number.getRandomInteger(nBit + phiBit)
            T1 = ( memKey.A * safePow( pubKey.H, w, pubKey.RSAN) ) % pubKey.RSAN

            T2_1 = safePow( pubKey.G, w, pubKey.RSAN)
            T2_2 = safePow( pubKey.H, memKey.e, pubKey.RSAN)
            T2_3 = safePow( pubKey.gPerp, r, pubKey.RSAN)
            T2 = (T2_1 * T2_2 * T2_3) % pubKey.RSAN
            
            Rv = number.getRandomInteger(hBit + phiBit + vBit)
            Rf = number.getRandomInteger(hBit + phiBit + secretBit)
            Re = number.getRandomInteger(hBit + phiBit + ePerpBit)
            Ree = number.getRandomInteger(hBit + phiBit + eBit + 1)
            Rw = number.getRandomInteger(hBit + 2*phiBit + hBit)
            Rr = number.getRandomInteger(hBit + 2*phiBit + hBit)
            Rew = number.getRandomInteger(2*eBit + nBit + hBit + 2*phiBit + 1)
            Rer = number.getRandomInteger(2*eBit + nBit + hBit + 2*phiBit + 1)
            Rbsn = number.getRandomInteger( secretBit )

            T1Perp_1 = safePow(T1, Re, pubKey.RSAN)
            T1Perp_2 = safePow(pubKey.R, Rf, pubKey.RSAN)
            T1Perp_3 = safePow(pubKey.S, Rv, pubKey.RSAN)
            T1Perp_4 = safePow(pubKey.H, -1*Rew, pubKey.RSAN)
            T1Perp = ( T1Perp_1 * T1Perp_2* T1Perp_3 * T1Perp_4 ) % pubKey.RSAN
            
            T2Perp_1 = safePow(pubKey.G, Rw, pubKey.RSAN)
            T2Perp_2 = safePow(pubKey.H, Re, pubKey.RSAN)
            T2Perp_3 = safePow(pubKey.gPerp, Rr, pubKey.RSAN)
            T2Perp = ( T2Perp_1 * T2Perp_2 *T2Perp_3 ) % pubKey.RSAN

            T3Perp_1 = safePow( T2, -1*Re, pubKey.RSAN )
            T3Perp_2 = safePow( pubKey.G, Rew, pubKey.RSAN )
            T3Perp_3 = safePow( pubKey.H, Ree, pubKey.RSAN )
            T3Perp_4 = safePow( pubKey.gPerp, Rer, pubKey.RSAN )
            T3Perp   = ( T3Perp_1 *T3Perp_2 *T3Perp_3 *T3Perp_4 ) % pubKey.RSAN

            B = safePow( pubKey.u, bsnPower, pubKey.pGroup )
            K = safePow( B, memKey.f , pubKey.pGroup)
            KPerp = safePow( B, Rf, pubKey.pGroup)

            C1 = SHA256.new()
            C1.update(str(pubKey.RSAN))
            C1.update(str(pubKey.gPerp))
            C1.update(str(pubKey.G))
            C1.update(str(pubKey.H))
            C1.update(str(pubKey.R))
            C1.update(str(pubKey.S))
            C1.update(str(pubKey.Z))
            C1.update(str(pubKey.pGroup))
            C1.update(str(pubKey.qGroup))
            C1.update(str(pubKey.u))
            C1.update(str(B))
            C1.update(str(K))
            C1.update(str(T1))
            C1.update(str(T2))
            C1.update(str(T1Perp))
            C1.update(str(T2Perp))
            C1.update(str(T3Perp))
            C1.update(str(KPerp))
            C1.update((msgHash.hexdigest()))
            C1Int = int( C1.hexdigest(), 16)
            self.B = B
            self.K = K
            self.T1 = T1
            self.T2 = T2
            self.C1 = C1Int
            self.Sv = Rv + C1Int * memKey.v
            self.Sf = Rf + C1Int * memKey.f
            self.Se = Re + C1Int * (memKey.e - E)
            self.Sr = Rr + C1Int * r
            self.Sw = Rw + C1Int * w
            self.Sew = Rew + C1Int * w * memKey.e
            self.See = Ree + C1Int * (memKey.e**2)
            self.Ser = Rer + C1Int * memKey.e * r
            self.Sbsn = Rbsn + C1Int * memKey.f

    def readfrom( self, fileName):
        f = open(fileName, "r")
        self.B = int(f.readline())
        self.K = int(f.readline())
        self.T1 = int(f.readline())
        self.T2 = int(f.readline())
        self.C1 = int(f.readline())
        self.Sv = int(f.readline())
        self.Sf = int(f.readline())
        self.Se = int(f.readline())
        self.Sr = int(f.readline())
        self.Sw = int(f.readline())
        self.Sew = int(f.readline())
        self.See = int(f.readline())
        self.Ser = int(f.readline())
        self.Sbsn = int(f.readline())
        f.close()
    def write( self, fileName):
        f = open(fileName, "w")
        writeline( f, self.B)
        writeline( f, self.K)
        writeline( f, self.T1)
        writeline( f, self.T2)
        writeline( f, self.C1)
        writeline( f, self.Sv)
        writeline( f, self.Sf)
        writeline( f, self.Se)
        writeline( f, self.Sr)
        writeline( f, self.Sw)
        writeline( f, self.Sew)
        writeline( f, self.See)
        writeline( f, self.Ser)
        writeline( f, self.Sbsn)
        f.close()
    def verify( self, pubKey, bsn, msg):
        SePerp = self.Se + self.C1*(E)
        
        bsnPower = bsnPow( bsn, pubKey.pGroup, pubKey.qGroup)
        B = safePow( pubKey.u, bsnPower, pubKey.pGroup )
        msgHash = SHA256.new()
        msgHash.update(msg)
        if( self.B != B):
            return False
        
        

        T1Head_1 = safePow( pubKey.Z, -1*self.C1, pubKey.RSAN)
        T1Head_2 = safePow( self.T1, SePerp, pubKey.RSAN)
        T1Head_3 = safePow( pubKey.R, self.Sf, pubKey.RSAN)
        T1Head_4 = safePow( pubKey.S, self.Sv, pubKey.RSAN)
        T1Head_5 = safePow( pubKey.H, -1*self.Sew, pubKey.RSAN)
        T1Head = ( T1Head_1 * T1Head_2 * T1Head_3 * T1Head_4 *T1Head_5 ) % pubKey.RSAN

        T2Head_1 = safePow( self.T2, -1*self.C1, pubKey.RSAN )
        T2Head_2 = safePow( pubKey.G, self.Sw, pubKey.RSAN )
        T2Head_3 = safePow( pubKey.H, SePerp, pubKey.RSAN )
        T2Head_4 = safePow( pubKey.gPerp, self.Sr, pubKey.RSAN )
        T2Head = ( T2Head_1 * T2Head_2 * T2Head_3 * T2Head_4) % pubKey.RSAN

        T3Head_1 = safePow( self.T2, -1*SePerp, pubKey.RSAN)
        T3Head_2 = safePow( pubKey.G, self.Sew, pubKey.RSAN)
        T3Head_3 = safePow( pubKey.H, self.See, pubKey.RSAN)
        T3Head_4 = safePow( pubKey.gPerp, self.Ser, pubKey.RSAN)
        T3Head = ( T3Head_1 *T3Head_2 * T3Head_3 * T3Head_4 ) % pubKey.RSAN

        KHead_1 = safePow( self.K, -1*self.C1, pubKey.pGroup)
        KHead_2 = safePow( self.B, self.Sf, pubKey.pGroup)
        KHead = ( KHead_1 * KHead_2) % pubKey.pGroup

        Check = SHA256.new()
        Check.update(str(pubKey.RSAN))
        Check.update(str(pubKey.gPerp))
        Check.update(str(pubKey.G))
        Check.update(str(pubKey.H))
        Check.update(str(pubKey.R))
        Check.update(str(pubKey.S))
        Check.update(str(pubKey.Z))
        Check.update(str(pubKey.pGroup))
        Check.update(str(pubKey.qGroup))
        Check.update(str(pubKey.u))
        Check.update(str(self.B))
        Check.update(str(self.K))
        Check.update(str(self.T1))
        Check.update(str(self.T2))
        Check.update(str(T1Head))
        Check.update(str(T2Head))
        Check.update(str(T3Head))
        Check.update(str(KHead))
        Check.update((msgHash.hexdigest()))
        CheckInt = int( Check.hexdigest(), 16)

        if( CheckInt == self.C1):
            return True
        else:
            return False
        
def safePow( x, n, MOD):
    tmpx = 1
    tmpn = n
    bitList = []
    if n < 0:
        tmpn *= -1
    while(tmpn != 0):
        bitList.append(tmpn % 2)
        tmpn = tmpn / 2
    bitList.reverse()

    for i in bitList:
        tmpx = (tmpx**2) % MOD
        if(i == 1):
            tmpx = (tmpx * x) % MOD
    if n < 0:
        tmpx = number.inverse(tmpx, MOD)
    return tmpx

def bsnPow( bsn, pGroup, qGroup):
    bsnHash = SHA256.new()
    bsnHash.update(bsn)
    bsnHashInt = int( bsnHash.hexdigest(), 16)
    bsnPower = safePow( bsnPower, bsnHashInt, pGroup)
    return bsnPower
