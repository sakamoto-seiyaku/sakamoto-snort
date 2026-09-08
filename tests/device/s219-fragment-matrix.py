"""Controlled wire vectors and independently declared platform inputs for S219."""
import ipaddress, struct
A=dict(uid=21900,ifindex=31,context=1,availability=7,direction=3,provenance=2)
B=dict(uid=21901,ifindex=32,context=2,availability=7,direction=1,provenance=3)
UNKNOWN=dict(uid=0,ifindex=0,context=0,availability=0,direction=0,provenance=0)
def checksum(data):
 if len(data)&1:data+=b'\0'
 value=sum(struct.unpack('!'+str(len(data)//2)+'H',data))
 while value>>16:value=(value&65535)+(value>>16)
 return (~value)&65535

def fragments(family,identity,port):
 source=ipaddress.ip_address('198.18.219.1' if family==4 else 'fd00:219::1').packed
 destination=ipaddress.ip_address('198.18.219.2' if family==4 else 'fd00:219::2').packed
 payload=bytes((identity+i)%251 for i in range(24))
 udp=struct.pack('!HHHH',port,40639,len(payload)+8,0)+payload
 pseudo=source+destination+(struct.pack('!BBH',0,17,len(udp)) if family==4 else struct.pack('!I3xB',len(udp),17))
 udp=udp[:6]+struct.pack('!H',checksum(pseudo+udp) or 65535)+udp[8:]
 result=[]
 for offset in (0,16):
  part=udp[offset:offset+16];more=offset==0
  if family==4:
   header=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(part),identity,offset//8|(0x2000 if more else 0),64,17,0,source,destination)
   header=header[:10]+struct.pack('!H',checksum(header))+header[12:]
  else:header=struct.pack('!IHBB16s16s',6<<28,8+len(part),44,64,source,destination)+struct.pack('!BBHI',17,0,offset|int(more),identity)
  result.append((header+part).hex())
 return result

def matrix():
 result=[];number=0
 variants=[('known-first',A,UNKNOWN,False,False),('known-late',A,UNKNOWN,True,False),('unknown-first',UNKNOWN,A,False,False),('unknown-late',UNKNOWN,A,True,False),('different-first',A,B,False,False),('different-late',B,A,True,False),('snapshot-change',A,B,False,True)]
 for family in (4,6):
  for index,(label,first,other,reverse,change) in enumerate(variants):
   identity=21900+(0 if family==4 else 100)+index;port=45200+index
   wire=fragments(family,identity,port);order=[1,0] if reverse else [0,1]
   entries=[]
   for offset in order:
    number+=1;entries.append(dict(case=number,hex=wire[offset],worker=(index+offset)%2,facts=dict(first if offset==0 else other),offset=offset*16))
   result.append(dict(label=f'{family}-{label}',family=family,identity=identity,port=port,expected=dict(first),blocked=first==A,packets=entries,snapshot_change=change,no_first=False))
  number+=1
  result.append(dict(label=f'{family}-no-first',family=family,identity=identity+1,port=45210,expected=None,blocked=False,packets=[dict(case=number,hex=fragments(family,identity+1,45210)[1],worker=1,facts=dict(A),offset=16)],snapshot_change=False,no_first=True))
 return result
