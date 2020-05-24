import socket

addr = "192.168.0.159"

sock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
while true:
    for port in range(0,1000):
        for n in range(0,100):
            sock.sendto([1], (addr, port))

print(msg)
