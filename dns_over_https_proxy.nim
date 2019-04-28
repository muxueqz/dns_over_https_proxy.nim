import net
import strutils
import streams
import httpclient, json


proc query_dns(name: string): string =
  let client = newHttpClient()
  client.headers = newHttpHeaders({
      "accept": "application/dns-json",
      })
  var url = "https://cloudflare-dns.com/dns-query?name=$1&type=$2" % [name, "A"]
  echo(url)
  var response = client.request(url,
                  HttpGet)
  let jsonNode = parseJson(response.body)
  # TODO
  for answer in jsonNode["Answer"]:
    if answer["type"].getInt() == 1:
      result = answer["data"].getStr()

proc parse_dns(data:string): string =
  var
    ini = 12
    lon = ord(data[ini])
    dominio = ""
  echo "lon:",lon
    # tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
    # if tipo == 0:                     # Standard query
  while lon != 0:
    dominio = dominio & data[ini+1 .. ini+lon] & "."
    ini += lon+1
    lon = ord(data[ini])
  echo dominio

  result = data[..1] & "\x81\x80"
  var ac = data[4 .. 5] & data[4..5] & "\x00\x00\x00\x00"   # Questions and Answers Counts
  result = result & ac
  ac = data[12..^1]
  result = result & ac
  ac = "\xc0\x0c" 
  result = result & ac
  ac = "\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"             # Response type, ttl and resource data length -> 4 bytes
  result = result & ac
  # var ip = "192.168.1.10"
  # var ip = query_dns("g.cn")
  var ip = query_dns(dominio)

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

echo "Listen"
while true:
  var data = newStringOfCap(4096)
  echo socket.recvfrom(data, 1024, address, port)
  echo data
  packet = parse_dns(data)

  socket.sendTo(address, port, packet)
