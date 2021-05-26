#!/usr/bin/env python3
#
#  modified script originally created by Judy Novak for SEC503.
#  sending an ICMP echo request with overalpping fragments
#  and waiting for a response.
#

from scapy.all import *
from random import randrange
dst = '10.5.1.84'

#
# the intend is to send a set of fragments like:
#
#  FRAGMENTAABBAABB
#          BBAABBAACCCCCCCCDDEEDDEE
#                          EEDDEEDDFFFFFFFF
#
#  the payload was selected such that it is checksum neutral no
#  matter how the overlap is resolved.
#

# payload1='FRAGMENTAABBAABB'
payload1='FRAGMENTBBAA'
# payload2='BBAABBAACCCCCCCCDDEEDDEE'
payload2='BBAABBAACCCCCCCC'
payload3='EEDDEEDDFFFFFFFF'
payloadA='FRAGMENTAABBAABBCCCCCCCCDDEEDDEEFFFFFFFF';
payloadB='FRAGMENTBBAABBAACCCCCCCCEEDDEEDDFFFFFFFF';

i = IP(dst=dst, proto=1)
icmpid=randrange(0,65535)
icmpseq=randrange(0,65535)
ipid=randrange(0,65535)
i.id=ipid
icmp = ICMP(type=8,code=0,id=icmpid,seq=icmpseq)
ippacket=IP(raw(i/icmp/payloadA))
icmp.chksum=ippacket['ICMP'].chksum
print(icmp.chksum)
ippacket=IP(raw(i/icmp/payloadB))
print(ippacket['ICMP'].chksum)
i.flags='MF'
i.offset=0
frag1=i/icmp/payload1
i.flags='MF'
i.frag=2
frag2=i/payload2
i.flags=''
i.frag=4
frag3=i/payload3
send(frag1)
send(frag2)
send(frag3)

