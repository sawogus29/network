from network import *
from network import _BROADCAST_IP

print('Creating AP') #Host보다 AP먼저 만들어야 함.(arp 미구현으로 인해)
ap = AP()

print('Creating Hosts')
h1 = Host()
h2 = Host()

print('Creating Links')
link1 = Link()
link2 = Link()

h1.connect(link1)
ap.lan.connect(link1)
h2.connect(link2)
ap.lan.connect(link2)
print(link1, link2)
print('Hosts gets IP')
h1.autoIP()
h2.autoIP()
print(h1, h2)
print('Start simulation')
print('-------------------')
#ap.pingAll()
print('h1 ping h2')
h1.ping(3)
'''
print(ap._counter)
print(ap)
print(h1.ipAddr, h1.macAddr)
print(h2.ipAddr, h2.macAddr)
'''