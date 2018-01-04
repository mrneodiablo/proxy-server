#!/usr/bin/env python
from sys import argv
import socket
import threading
script, host = argv
address = socket.gethostname(host)
ports = []
class Scanthread(threading.thread):
	def __init__(self, startport, endport, ports):
		threading.Thread.__init__(self)
		self.startport = startport
		self.endport = endport

	def run(self):
		while self.startport <= self.endport:
			s = socket.socket()
			s.settimeout(.3)
			result = s.connect_ex((address.self.startport))
			if result == 0:
				print "port", self.startport, "is Open"
				ports.append(self.startport)
			self.startport += 1
		s.close()

print "Scaning all port...."
port = 0
threads = []
while port <60000:
   t = Scanthread(port,port+5000, ports)
   t.start()
   threads.append(t)
   port += 5000
for t in threads:
   t.join()
if len(ports) == 0:
   print "All port is close."
else:
   ports.sort()
   print "Port open: ", ports
			 	
		
