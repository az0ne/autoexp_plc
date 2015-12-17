# Echo client program
import socket
import re
import os,sys

#HOST = '192.168.200.50'    # The remote host
#PORT = 9600              # The same port as used by the server
#s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#s.connect((HOST, PORT))

finsErrorsStrings = {
    0x0000000:None,
    0x0000001:'The header is not FINS (ASCII code)',
    0x0000002:'The data length is too long.',
    0x0000003:'The command is not supported.',
    0x0000020:'All connections are in use.',
    0x0000021:'The specified node is already connected.',
    0x0000022:'Attempt to access a protected node from an unspecified IP',
    0x0000023:'The client FINS node address is out of range.',
    0x0000024:'The same FINS node address is being used by the client and server.',
    0x0000025:'All the node addresses available for allocation have been used.',
    }

def int2str4(k):
    return chr((k>>24) & 0xff) + chr((k>>16) & 0xff) + chr((k>>8) & 0xff) + chr((k>>0) & 0xff)

def int2str3(k):
    return chr((k>>16) & 0xff) + chr((k>>8) & 0xff) + chr((k>>0) & 0xff)

def int2str2(k):
    return chr((k>>8) & 0xff) + chr((k>>0) & 0xff)

def binstr2int(s):
    n = 0
    for i in range(0, len(s)):
        n += ord(s[i]) * ( 1<<(8*( len(s)-i-1)))
    return n

def str2intlist(s):
    return [ord(c) for c in s]

def intlist2str(l):
  return ''.join([chr(e) for e in l])

def wordlist2str( wl):
    if wl[0] != 0xff:
        print '-- Neplatna'
        return ''
    cs  = ''
    for d in wl[1:]:
        n1 = ((d>>8) & 0xFF)
        n2 = (d & 0xFF)
        if n1==0:
            break
        if n2==0:
            cs += chr( n1)
            break
        cs += chr( n1) + chr( n2)
    return cs

class FinsTCPframe():
    def __init__(self, cmdData='',  rawFinsCmd = None,  cmdFlags = None,  DA1=None,  SA1=None,  MRC=None,  SRC=None,  command=0x02, errorCode=0x00, serverAdr = 0,  clientAdr = 0, rawTcpFrame=None ):
        self.FINScommandFlags=['ICF','RSV','GCT','DNA','DA1','DA2','SNA','SA1','SA2','SID','MRC','SRC','data']
        if rawTcpFrame:
            self.fromRaw = True
            self.rawTcpFrame = rawTcpFrame
        else:
            self.fromRaw = False
            if (MRC or SRC or cmdData) :
                #have some command data
                commandFlags  = [
                    0x80, # ICF
                    0x00, # RSV 'RSV':0
                    0x02, #'GCT':0x02
                    0x00, #'DNA':0
                    serverAdr, #'DA1':0
                    0x00, #'DA2':0
                    0x00, #'SNA':0
                    0x00, #'SA1':0
                    clientAdr, #'SA2':0
                    0x00,  #'SID':0
                    MRC, #'MRC':0
                    SRC, #'SRC':0
                ]
                if cmdFlags:
                    for k in cmdFlags.keys() :
                        commandFlags[ self.FINScommandFlags.index( k)] = cmdFlags[k]
                commandFrame = intlist2str(commandFlags) + cmdData
            else:
                #frame have TCPheader only or raw Fins Command Packet Provided
                if rawFinsCmd :
                    commandFrame = rawFinsCmd
                else:
                    commandFrame = ''
            self.rawTcpFrame ='FINS'
            self.rawTcpFrame += int2str4( 8 + len( commandFrame))    #frame length
            self.rawTcpFrame += int2str4( command)
            self.rawTcpFrame += int2str4( errorCode)
            self.rawTcpFrame += commandFrame

    def makeFrame(self):
        self.finsFrame = 'FINS'
        self.frameLength = 8 + len( self.finsCmdFrame)
        self.finsFrame += int2str4( self.frameLength)
        self.finsFrame += int2str4( self.finsCommand)
        self.finsFrame += int2str4( self.finsErrorCode)
        self.finsFrame += self.finsCmdFrame
        return self.finsFrame
    @property
    def raw(self):
        return self.rawTcpFrame
    @property
    def disassembled(self):
        asm = {
               'header'   : binstr2int( self.rawTcpFrame[ 0: 4] ),
               'length'   : binstr2int( self.rawTcpFrame[ 4: 8] ),
               'command' : binstr2int( self.rawTcpFrame[ 8:12] ),
               'errCode' : binstr2int( self.rawTcpFrame[12:16] ),
        }
        if( asm['command'] == 2) :
            asm[ 'ICF'] = binstr2int( self.rawTcpFrame[16])
            asm[ 'RSV'] = binstr2int( self.rawTcpFrame[17])
            asm[ 'GCT'] = binstr2int( self.rawTcpFrame[18])
            asm[ 'DNA'] = binstr2int( self.rawTcpFrame[19])
            asm[ 'DA1'] = binstr2int( self.rawTcpFrame[20])
            asm[ 'DA2'] = binstr2int( self.rawTcpFrame[21])
            asm[ 'SNA'] = binstr2int( self.rawTcpFrame[22])
            asm[ 'SA1'] = binstr2int( self.rawTcpFrame[23])
            asm[ 'SA2'] = binstr2int( self.rawTcpFrame[24])
            asm[ 'SID'] = binstr2int( self.rawTcpFrame[25])
            asm[ 'MRC'] = binstr2int( self.rawTcpFrame[26])
            asm[ 'SRC'] = binstr2int( self.rawTcpFrame[27])
            if self.fromRaw :
                #decode from response
                asm[ 'MRES'] = binstr2int( self.rawTcpFrame[28])
                asm[ 'SRES'] = binstr2int( self.rawTcpFrame[29])
                asm['response'] = self.rawTcpFrame[30:]
            else :
                asm['cmd'] = self.rawTcpFrame[28:]
        return asm
    @property
    def error(self):
        #return None if ok, else errorstring as string
        try:
            ec = binstr2int( self.rawTcpFrame[12:16])
            if ec == 0:
                ec = None
        except:
            ec = 'Error code not found'%self.finsErrorCode
        return ec
    @property
    def command(self):
        return binstr2int( self.rawTcpFrame[ 8:12])
    @property
    def commandResponse(self ):
        return  self.rawTcpFrame[30:]
    @property
    def finsData(self):
        """Return raw data after FINS TCP header"""
        return  self.rawTcpFrame[16:]
    def __str__(self):
        asm = self.disassembled
        str = ''.join([ "{0}:{1} ".format(k, asm[k], ) for k in asm.keys()])
        return str

class OmronPlcFinsTcp():
    def __init__(self, host, port):
        self.port = port
        self.host = host
        self.sock = None
        self.open = False
        self.clientNode = 0
        self.serverNode = 0
        self.sid=0x04
    @property
    def _nextSid(self):
        self.sid = (self.sid + 1 ) & 0xff
        return self.sid
    def openn(self):
        if self.open :
            #close if already open
            self.sock.close()
            self.open = False
        #open socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        self.sock.settimeout( 1)
        #start establish fins communication
        #print 'FINS cmd: request address'
        c1 = FinsTCPframe ( command = 0,  rawFinsCmd = int2str4(0))
        #print "Sending: " + str( c1)
        self._send( c1.raw)
        r1raw = self._recieve()
        r1 = FinsTCPframe( rawTcpFrame = r1raw )
        print "Recieved: " + str( r1)
        if r1.error:
            print 'Error in adress assign response: %s' % r1.error
            try :
                print ' - this mean>%s' % finsErrorsStrings[r1.error]
            except :
                pass
            return False
        #set client and server address against response
        if r1.command != 1 :
            print 'Error bad response for  adress assign command: ' % r1.command
            return False
        self.clientNode = binstr2int( r1.finsData[0:4])
        self.serverNode = binstr2int( r1.finsData[4:8])
        print 'FINS address client:{0},server{1}'.format(self.clientNode, self.serverNode, )
        #Get PLC type as test dummmy command
        return self.doFinsCommand( MRC=0x05, SRC=0x01, cmdData = '\x00')[0:20]
    def doFinsCommand(self, MRC,  SRC,  cmdData):
        #cmdData='',  rawFinsCmd = None,  cmdFlags = None,  DA1=None,  SA1=None,  MRC=None,  SRC=None,  command=0x02, errorCode=0x00, serverAdr = 0,  clientAdr = 0, rawTcpFrame=None ):
        c = FinsTCPframe(MRC=MRC, SRC=SRC, cmdData = cmdData,  serverAdr=self.serverNode, clientAdr=self.clientNode,  cmdFlags = {'SID':self._nextSid} )
        #print "Sending: " + str( c)
        self._send(c.raw)
        r_raw = self._recieve()
        r = FinsTCPframe( rawTcpFrame = r_raw )
        #print "Recieved: " + str( r)
        #print " disasm>" + str(r.disassembled)
        #TODO: check error and status..
        return r.commandResponse
    def close(self):
        self.sock.close()
        self.open = False
    def _send(self,  raw):
        self.sock.send( raw)
        #print ' Send:' + repr(raw)
    def _recieve(self):
        pr = self.sock.recv(8)
        length = binstr2int( pr[4:8])
        r = pr + self.sock.recv( length)
        #print ' Recv:' + repr(r)
        return r


class OmronPLC():
    def __init__(self):
        self.conType = None
        self.plcType = None
        self.MEMCODES = {
           #'MemType':(word,bit)
           'C':(0x30, 0xB0),
           'W':(0x31, 0xB1),
           'H':(0x32, 0xB2),
           'A':(0x33, 0xB3),
           'D':(0x02, 0x82),
        }

    def openFins(self, address,  port=9600):
        self.conType = 'FINS'
        self.conn = OmronPlcFinsTcp( address,  port)
        self.plcType = self.conn.openn()
        if (self.plcType) :
            print 'Open successfull to ',  self.plcType,  'at ', address
        else :
            raise Exception('Failed to open PLC')
    def doRawFinsCommand(self,  **kvarg):
        self.conn.doFinsCommand( kvarg)
    def close(self):
        if self.conType == 'FINS':
            self.conn.close()
    def readMemC(self, mem,  length ):
        memSpec= re.search('(.)([0-9]*):?([0-9]*)',mem).groups()
        ( memCodeB,  memCodeW) = self.MEMCODES[ memSpec[0]]
        #construct mem specification form
        if memSpec[2] :
            #BIT specs
            memAdr = chr( memCodeB) + int2str2( int(memSpec[1])) + chr( int(memSpec[2]))
        else:
            #Word Spec
            memAdr = chr( memCodeW) + int2str2( int(memSpec[1])) + chr( 0)
        rawres = self.conn.doFinsCommand( MRC=0x01, SRC=0x01,
                                    cmdData = memAdr + int2str2(length*2))
        if memSpec[2] :
            #bit spec
            res = list( rawres)
        else:
            res = [ ord( rawres[i]) * 256 + ord( rawres[ i+1]) for i in range(0,  len(rawres)/2, 2)]
        return res

    def writeMemC(self, mem, wdata ):
        memSpec= re.search('(.)([0-9]*):?([0-9]*)',mem).groups()
        ( memCodeB,  memCodeW) = self.MEMCODES[ memSpec[0]]
        #construct mem specification form
        if memSpec[2] :
            #BIT specs
            raise Exception("Bit memory write : Not Implemented")
        else:
            #Word Spec
            memAdr = chr( memCodeW) + int2str2( int(memSpec[1])) + chr( 0)
            rawdata = ''
            for d in wdata:
                rawdata += int2str2(d)
        rawres = self.conn.doFinsCommand( MRC=0x01, SRC=0x02,
                                    cmdData = memAdr + int2str2(len(rawdata)/2) + rawdata )
        return rawres


import time

def main(plcip):

    plc = OmronPLC( )
    plc.openFins(plcip, 9600)
    plc.close()

if __name__ == "__main__":
    plcip = sys.argv[1]
    main(plcip)
