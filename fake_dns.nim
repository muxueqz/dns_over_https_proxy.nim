import net
import strutils
import streams

proc parse_dns(data:string): string =
  result = data[..1] & "\x81\x80"
  var ac = data[4 .. 5] & data[4..5] & "\x00\x00\x00\x00"   # Questions and Answers Counts
  result = result & ac
  ac = data[12..^1]
  result = result & ac
  ac = "\xc0\x0c" 
  result = result & ac
  ac = "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"             # Response type, ttl and resource data length -> 4 bytes
  result = result & ac
  var ip = "192.168.1.10"

  var new_ac = ""
  for i in ip.split('.'):
    new_ac.add chr(i.parseInt)
  result = result & new_ac

var socket = newSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)

socket.bindAddr(Port(15353))

var
  client: Socket
  address = ""
  port: Port
  packet = ""
while true:
  var data = newStringOfCap(4096)
  echo socket.recvfrom(data, 1024, address, port)
  echo data
  packet = parse_dns(data)

  socket.sendTo(address, port, packet)
