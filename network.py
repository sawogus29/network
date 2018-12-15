import sys

_BROADCAST_MAC = 0xffffffffffff
_BROADCAST_IP = 0xffffffff


class ARPTable:
    _arpTable = {_BROADCAST_IP: _BROADCAST_MAC, }

    def __init__(self):
        pass

    @classmethod
    def arp(cls, ip):
        return cls._arpTable.get(ip)

    @classmethod
    def append(cls, ip, mac):
        cls._arpTable[ip] = mac


class Host:
    def __init__(self):
        self._hostName = ""
        self._ipAddr = 0
        self._netmask = 0
        self._nic = NetworkInterfaceCard(self)
        self._gatewayIP = 0
        self._counter = Counter()

        self._arpTable = {}
        self._dhcpClient = DHCPClient(self)

    @property
    def macAddr(self):
        return self._nic.macAddr

    @macAddr.setter
    def macAddr(self, value):
        self._nic.macAddr = value

    @property
    def hostName(self):
        return self._hostName

    @hostName.setter
    def hostName(self, value):
        self._hostName = value

    @property
    def ipAddr(self):
        return self._ipAddr

    @ipAddr.setter
    def ipAddr(self, value):
        self._ipAddr = value

    @property
    def gatewayIP(self):
        return self._gatewayIP

    @gatewayIP.setter
    def gatewayIP(self, value):
        self._gatewayIP = value

    @property
    def netmask(self):
        return self._netmask

    @netmask.setter
    def netmask(self, value):
        self._netmask = value

    def connect(self, link):
        self._nic.connect(link)

    def disconnect(self):
        self._nic.disconnect()

    def arp(self, ipAddr):
        def mask(ip, netmask):
            return ip // (2 ** (32 - netmask))

        if ipAddr == _BROADCAST_IP or mask(ipAddr, self._netmask) == mask(self._ipAddr, self._netmask):
            return ARPTable.arp(ipAddr)

        else:
            return ARPTable.arp(self._gatewayIP)

    def autoIP(self):
        self._dhcpClient.dhcpDiscover()

    def send(self, dstIP, data):
        packet = Packet(self.ipAddr, dstIP, data)

        self._counter.txCount(packet)

        dstMAC = self.arp(dstIP)
        if dstMAC is not None:
            self._nic.send(dstMAC, packet)
        else:
            print('ARP failed')

    def receive(self, packet):

        self._counter.rxCount(packet)

        if isinstance(packet.data, Segment):
            segment = packet.data
            port = segment.dstPort

            if port == 68:
                self._dhcpClient.receive(segment.data)
        else:
            if packet.data[0] == 'ping':
                self.send(packet.srcIP, ('ping ack',))
            elif packet.data[0] == 'ping ack':
                print(packet.srcIP, ': ping ack')

    def ping(self, dstIP):
        self.send(dstIP, ('ping',))

    def __str__(self):
        return str(self._ipAddr)


class NetworkInterface:
    def __init__(self, nic, id=0):
        self._link = None
        self._nic = nic
        self._id = id

    def connect(self, link):
        self._link = link
        self._link.register(self)

    def disconnect(self):
        self._link = None
        self._link.remove(self)

    def send(self, frame):
        if self._link is not None:
            print(self, 'send')
            self._link.send(frame, self)
        else:
            print(self, 'Link Down!')

    def receive(self, frame):
        print(self, 'recieve')
        assert self._nic is not None
        self._nic.receive(frame, self)

    def __str__(self):
        assert self._nic is not None
        return str(self._nic) + '(' + str(self._id) + ')'


class NetworkInterfaceCard():
    def __init__(self, host):
        self._macAddr = MacFactory.getNewMac()
        self._host = host
        self._interface = NetworkInterface(self)

    def connect(self, link):
        self._interface.connect(link)

    def disconnect(self):
        self._interface.disconnect()

    @property
    def macAddr(self):
        return self._macAddr

    @macAddr.setter
    def macAddr(self, value):
        self._macAddr = value

    def send(self, dstMAC, packet):
        frame = Frame(self._macAddr, dstMAC, packet)

        assert self._interface is not None
        print(self._macAddr, 'nic send')
        self._interface.send(frame)

    def receive(self, frame, interface):
        if frame.dstMAC == self._macAddr or frame.dstMAC == _BROADCAST_MAC:
            print(self._macAddr, 'nic recieve')

            if self._host is not None:
                self._host.receive(frame.packet)
        else:
            pass

    def __str__(self):
        return str(self._macAddr)


class LAN:
    def __init__(self, host):
        self._macAddr = MacFactory.getNewMac()
        self._host = host
        ARPTable.append(host.ipAddr, self._macAddr)
        self._MAX_INTERFACES = 4
        self._interfaceCount = 0
        self._interfaces = [NetworkInterface(self, i) for i in range(self._MAX_INTERFACES)]
        self._switchTable = {}

    def connect(self, link):
        count = self._interfaceCount
        if count < self._MAX_INTERFACES:
            self._interfaces[count].connect(link)
            self._interfaceCount += 1
        else:
            print('full')

    def disconnect(self):
        # TODO : which interface?
        self._interfaces.pop().disconnect()

    @property
    def macAddr(self):
        return self._macAddr

    @macAddr.setter
    def macAddr(self, value):
        self._macAddr = value

    def send(self, dstMAC, packet):
        frame = Frame(self._macAddr, dstMAC, packet)

        if dstMAC == _BROADCAST_MAC:
            for i in self._interfaces:
                i.send(frame)

    def receive(self, frame, interface):
        print(self._macAddr, 'LAN recieve')

        # if frame.srcMAC not in self._switchTable:
        self._switchTable[frame.srcMAC] = interface

        if frame.dstMAC in self._switchTable:
            if self._switchTable[frame.dstMAC] != interface:
                self._switchTable[frame.dstMAC].send(frame)
            else:
                pass
        # self
        elif frame.dstMAC == self._macAddr:
            self._host.receive(frame.packet)
        # broadcast
        elif frame.dstMAC == _BROADCAST_MAC:
            if self._host is not None:
                self._host.receive(frame.packet)
            for i in self._interfaces:
                if i != interface:
                    i.send(frame)
        # not found -> flooding
        else:
            for i in self._interfaces:
                if i != interface:
                    i.send(frame)

    def __str__(self):
        return str(self._macAddr)


class AP:
    def __init__(self):
        self._ipAddr = 1
        self._netmask = 24
        self._lan = LAN(self)
        self._dhcpServer = DHCPServer(self)
        self._counter = Counter()

    @property
    def ipAddr(self):
        return self._ipAddr

    @property
    def lan(self):
        return self._lan

    def receive(self, packet):
        print(self, 'AP recieve')
        self._counter.rxCount(packet)
        if isinstance(packet.data, Segment):
            segment = packet.data
            port = segment.dstPort
            if port == 67:
                self._dhcpServer.receive(segment.data)
        else:
            if packet.data[0] == 'ping':
                self.send(packet.srcIP, ('ping ack',))
            elif packet.data[0] == 'ping ack':
                print(packet.srcIP, ': ping ack')

    def send(self, dstIP, data):
        dstMAC = self.arp(dstIP)
        assert dstMAC is not None
        packet = Packet(self._ipAddr, dstIP, data)
        self._counter.txCount(packet)
        self._lan.send(dstMAC, packet)

    def pingAll(self):
        self.send(_BROADCAST_IP, ('ping',))

    def arp(self, ipAddr):
        def mask(ip, netmask):
            return ip // (2**(32-netmask))

        if _BROADCAST_IP or mask(ipAddr, self._netmask) == mask(self._ipAddr, self._netmask):
            return ARPTable.arp(ipAddr)

    def __str__(self):
        return str(self._ipAddr)


class DHCPClient:
    def __init__(self, host):
        self._host = host
        self._acceptFlag = False

    def send(self, message):
        segment = Segment(67, message)
        self._host.send(_BROADCAST_IP, segment)

    def receive(self, message):
        if message[0] == 'dhcp offer':
            self.acceptOffer(message[1], message[2], message[3])
        if message[0] == 'dhcp expire':
            self._host.ipAddr = 0
            self.dhcpDiscover()

    def dhcpDiscover(self):
        self._acceptFlag = True
        discoverMessage = ('dhcp discover', 0)
        self.send(discoverMessage)

    def acceptOffer(self, offerIP, gatewayIP, netmask):
        if self._acceptFlag == True:
            self._host.ipAddr = offerIP
            self._host.gatewayIP = gatewayIP
            self._host.netmask = netmask
            self._acceptFlag = False
            ARPTable.append(self._host.ipAddr, self._host.macAddr)
        else:
            print(self._host.ipAddr, 'this is not mine')


class DHCPServer:
    def __init__(self, host):
        self._host = host
        assert self._host._ipAddr == 1
        self._netmask = host._netmask
        self._lowerBound = 2
        self._upperBound = 255
        self._ipList = []

    def send(self, message):
        segment = Segment(68, message)
        self._host.send(_BROADCAST_IP, segment)

    def receive(self, message):
        if message[0] == 'dhcp discover':
            self.dhcpOffer()

    def setPool(self, lowerBound, upperBound):
        if lowerBound < upperBound:
            self._lowerBound = lowerBound
            self._upperBound = upperBound
            self._ipList = []
            self.dhcpExpire()

    def dhcpOffer(self):
        for i in range(self._lowerBound, self._upperBound + 1):
            if i not in self._ipList:
                self._ipList.append(i)
                # offerIP, gatewayIP
                message = ('dhcp offer', i, self._host.ipAddr, self._netmask)
                self.send(message)
                return
        print('No available IP')

    def dhcpExpire(self):
        message = ('dhcp expire', 0)
        self.send(message)


class Link:
    def __init__(self):
        self._interfaceList = []
        self._down = False

    def register(self, interface):
        self._interfaceList.append(interface)

    def remove(self, interface):
        self._interfaceList.remove(interface)

    def send(self, frame, sender):
        if self._down == False:
            for i in self._interfaceList:
                if i != sender:
                    i.receive(frame)

    def down(self):
        self._down = True

    def uo(self):
        self._down = False

    def __str__(self):
        result = 'Link : '
        result += '---'.join(map(str, self._interfaceList))
        return result


class Segment:
    def __init__(self, dstPort, data):
        self._dstPort = dstPort
        self._data = data

    @property
    def dstPort(self):
        return self._dstPort

    @property
    def data(self):
        return self._data


class Packet:
    def __init__(self, srcIP, dstIP, data):
        self._srcIP = srcIP
        self._dstIP = dstIP
        self._data = data

    @property
    def srcIP(self):
        return self._srcIP

    @property
    def data(self):
        return self._data

    def __str__(self):
        print('src :', self._srcIP, ', dst :', self._dstIP)


class Frame:
    def __init__(self, srcMAC, dstMAC, packet):
        self._packet = packet
        self._srcMAC = srcMAC
        self._dstMAC = dstMAC

    @property
    def srcMAC(self):
        return self._srcMAC

    @property
    def dstMAC(self):
        return self._dstMAC

    @property
    def packet(self):
        return self._packet

    def __str__(self):
        print('src :', self._srcMAC, ', dst :', self._dstMAC)


class Counter:
    def __init__(self):
        self._rxPacket = 0
        self._txPacket = 0
        self._rxByte = 0
        self._txByte = 0

    def rxCount(self, packet):
        self._rxPacket += 1
        self._rxByte += sys.getsizeof(packet)

    def txCount(self, packet):
        self._txPacket += 1
        self._txByte += sys.getsizeof(packet)

    def __str__(self):
        return ('txPacket : ' + str(self._txPacket) + ', rxPacket :' + str(self._rxPacket) +
                '\ntxByte : ' + str(self._txByte) + ', rxByte : ' + str(self._rxByte))


class MacFactory:
    _macCount = 100

    def __init__(self):
        pass

    @classmethod
    def getNewMac(cls):
        temp = cls._macCount
        cls._macCount += 1
        return temp
