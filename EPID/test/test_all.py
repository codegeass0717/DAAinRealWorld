import os
import sys
os.chdir(sys.path[0])
sys.path.append('../')
from Module import *

issuer = Issuer()
user1 = Member()

print ' * Generating issuer\'s keys'
os.chdir('../issuer/TestData')
issuer.generate_keys('testKey')

print ' * Generating user\'s keys'
os.chdir('../../user/TestData')
user1.init_memkey1('testKey.pubkey', 'bsn', 'TMPSecret', 'Join')

os.chdir('../../issuer/TestData')
issuer.generate_tmpmemkey('testKey.prvkey', 'bsn', 'Join', 'member1')

os.chdir('../../user/TestData')
user1.init_memkey2('member1.tmpmemkey', 'TMPSecret', 'user1.memkey')

print ' * Testing sign and verify'
user1.load('testKey.pubkey', 'user1.memkey', bsnFile='bsn')
user1.sign('sign', msgFile='msg')
user1.verify('sign', msgFile='msg')

print ' * Pass'