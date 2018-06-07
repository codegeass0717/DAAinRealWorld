from Crypto.Util import number
from Crypto.Hash import SHA256
import sys
sys.path.append("../Module")
from common import *

fileName1 = raw_input("TMPmemberKey : ")
fileName2 = raw_input("TMPmemberSecret : ")
fileName3 = raw_input("MemberSecret : ")

memKey = memberKey()
memKey.mix(fileName1, fileName2)
memKey.write(fileName3)
