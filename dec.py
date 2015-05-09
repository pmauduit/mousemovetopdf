#!/usr/bin/env python

import pcap
from pyx import *

# if in the pcap file the current packet comes
# from the host, we don't care.
# this method detects if this is the case.

def fromHostToHID(p):
    if p[28].encode('hex') == '8d':
        return True
    return False

# 8bit signed repr
def heightBitSigned(us):
    return us - 256 if us > 127 else us

class HidPacket:
    def __init__(self, btnOn, offx, offy):
        self.btnOn = btnOn
        self.offx = offx
        self.offy = offy

# Dumps the significant data of the packet
def dumpSignificantData(p):
    print ":".join(x.encode('hex') for x in p[64:68])

def createHidPacket(p):
    return HidPacket(p[64].encode('hex') == '01', heightBitSigned(ord(p[65])),
            heightBitSigned(ord(p[66])))


paint = pcap.pcap("paint.cap")
numPckts = 0

c = canvas.canvas()

prevP = None
currP = None
while True:
    try:
        tstp,p = paint.next()
        if not fromHostToHID(p):
          if len(p) > 68:
              numPckts += 1
              dumpSignificantData(p)
              currP = createHidPacket(p)

              if prevP is not None:
                currP.offx += prevP.offx
                currP.offy += prevP.offy
                # button on between both packets, need to draw a line
                if prevP.btnOn and currP.btnOn:
                    c.stroke(path.line(prevP.offy, prevP.offx, currP.offy,
                        currP.offx))
              prevP = currP

    except StopIteration:
        break

c.writePDFfile("drawn")

print "%d packets read" % (numPckts, )

