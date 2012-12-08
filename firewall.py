from pox import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import *

# Get a logger
log = core.getLogger("fw")

class Firewall (object):
  """
  Firewall class.
  Extend this to implement some firewall functionality.
  Don't change the name or anything -- the eecore component
  expects it to be firewall.Firewall.
  """
  PRINT_BUFFERS = False
  TIMEOUT = 10
  BASIC_PORTS = 1024
  FTP_PORTS = 65536
  
  def __init__(self):
    """
    Constructor.
    Put your initialization code here.
    """
    
    #dictionary to hold all the monitoring data for the connections
    #K: Port number
    #V: Timer
    self.timers = {}
    
    #set that contains valid connections as csv of ext.IP, external port, internal ip, internal port
    #self.monitored_connections = set([])
    
    #dict that contains ports allowed due to FTP requests
    #key: tuple of (externIP, internIP)
    #v: another dictionary with k v pairs:
    #    key: internal port
    #    v: set of allowed ports for these three values
    self.allowed_ports = {}
    
    
    #dict that contains buffers for each connection.  
    #Two tiers of dictionaries with same keys as self.allowed_ports
    self.buffers = {}
    log.debug("Firewall initialized.")

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    
    # Banned port
    IPtuple = (str(flow.dst), str(flow.src))
    port = str(flow.dstport)
    if flow.dstport < self.BASIC_PORTS:
        if(flow.dstport == 21):
            #connection doesn't already exist
            #if(IPtuple in self.allowed_ports.keys()):
            #    log.debug("Duplicate FPT connection BLOCKED: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
            #    event.action.deny = True
            #else:
            log.debug("Allowed FTPcmd connection: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
            self.mark_monitored(event, flow)
            event.action.forward = True
        else:
            log.debug("Allowed connection: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
            event.action.forward = True
        return
    elif IPtuple in self.allowed_ports.keys() and flow.dstport < self.FTP_PORTS:
        log.debug("IP with allowed ports: " + IPtuple[0])
        log.debug("Allowed ports: " + ', '.join( self.allowed_ports[IPtuple]))
        for srcport in self.allowed_ports[IPtuple].keys():
            if(port in self.allowed_ports[IPtuple][srcport]):
                log.debug("Allowed FTP data connection to connect: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
                #remove once 1 TCP connection is made
                #cancel timer here. and delete timer.
                ip_and_port = (IPtuple, str(flow.dstport))
                if(len(self.timers[ip_and_port]) != 0):
                    self.timers[ip_and_port][0].cancel()
                    del(self.timers[ip_and_port][0])
                #port is no longer allowed if no more waiting timers for connections
                if(len(self.timers[ip_and_port]) == 0):
                    self.remove_port(IPtuple, srcport, port)
    
                event.action.forward = True
                return
        log.debug("DENIED connection, not using an open port: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
        event.action.deny = True
        return
    else:
        log.debug("DENIED connection: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
        event.action.deny = True
        return

  def _handle_MonitorData (self, event, packet, reverse):
    try:
        ip = packet.payload
        tcp = ip.payload
        data = tcp.payload
        
        if(reverse):
            IPtup = (ip.srcip.toStr(), ip.dstip.toStr())
        else:
            IPtup = (ip.dstip.toStr(), ip.srcip.toStr())
            
        try:
            data = self.buffers[IPtup][str(tcp.srcport)] + data    
        except KeyError:
            #first time initializing buffer
            if(self.PRINT_BUFFERS):
                log.debug("Initializing Buffer for: " + IPtup[0])
            if(not IPtup in self.buffers.keys()):
                self.buffers[IPtup] = {}
                self.buffers[IPtup][str(tcp.srcport)] = ''
        if(self.PRINT_BUFFERS):
            log.debug("Data: " + data)
            log.debug("Old Buffer: " + self.buffers[IPtup][str(tcp.srcport)])   
        
        #now split line based on newline  
        split = data.splitlines()
        if(self.PRINT_BUFFERS):
            log.debug("Split: " +  '---'.join(split))
        #if no EOL at end of string add it to buffer instead of processing now
        if(data != '' and data[-1] != '\n'):
            end = split[len(split)-1]
            self.buffers[IPtup][str(tcp.srcport)] = end
            #so buffer isn't processed
            split = split[0:len(split)-1]
        elif(data[-1] == '\n'):
            self.buffers[IPtup][str(tcp.srcport)] = ''
        if(self.PRINT_BUFFERS):
            log.debug("New Buffer: " + self.buffers[IPtup][str(tcp.srcport)])
        
        for line in split:
            if(line[0:4] == '229 '):
                line = line.split('|')
                port = line[len(line)-2]
                #not sure about reverse, not sure if IP will be formatted correctly
                self.open_port_with_timeout(port, IPtup, str(tcp.srcport), self.TIMEOUT)
                #self.monitored_connections.remove(IPStr)
            elif(line[0:4]  == '227 '):
                line = line.split('(')
                csvs = line[len(line)-1].split(')')[0] 
                ip_and_port = csvs.split(',')
                if(len(ip_and_port) == 6):
                    IP = ip_and_port[0]+'.'+ip_and_port[1]+'.'+ip_and_port[2]+'.'+ip_and_port[3]
                    if(reverse):
                        IPtup = (IP, ip.dstip.toStr())
                    else:
                        IPtup = (IP, ip.srcip.toStr())
                    port = str(int(ip_and_port[4])*256+int(ip_and_port[5]))
                    self.open_port_with_timeout(port, IPtup, str(tcp.srcport), self.TIMEOUT)
            elif(line[0:4] == '226 '):
                #close port before timeout
                try:
                    del(self.allowed_ports[IPtup][str(tcp.srcport)])
                except KeyError:
                    pass
                if(IPtup in self.allowed_ports.keys() and len(self.allowed_ports[IPtup].keys()) == 0):
                    del(self.allowed_ports[IPtup])
    except:
        pass
            
  def open_port_with_timeout(self, port, IPtup, srcport, timeout):
    ip_and_ports = (IPtup, port)
    log.debug("Opening port: " + IPtup[0] + ':' + port)

    if(not IPtup in self.allowed_ports.keys()):
        self.allowed_ports[IPtup] = {}
    if(not srcport in self.allowed_ports[IPtup].keys()):
        self.allowed_ports[IPtup][srcport] = set([])
    self.allowed_ports[IPtup][srcport].add(port)
    if(ip_and_ports not in self.timers.keys()):
        self.timers[ip_and_ports] = []
    self.timers[ip_and_ports].append(Timer(timeout, self.handle_timeout, args = [IPtup, srcport, port]))
    
  def mark_monitored(self, event, flow):
    #IPStr = flow.dst.toStr() + ',' + str(flow.dstport) + ',' + flow.src.toStr() + ',' + str(flow.srcport)
    #Same conneciton already exists!
    #if IPStr in self.monitored_connections:
    #    log.debug("Old connection still exists.  Resetting options.")
    #else:
    #    self.monitored_connections.add(IPStr)
    
    #monitor this connection in both directions
    #event.action.monitor_forward = True
    
    #TODO: only monitor backwards (incoming) traffic?
    event.action.monitor_backward = True
        
  def handle_timeout(self, IPtup, srcport, port):
    ip_and_port = (IPtup, port)
    if(IPtup in self.allowed_ports.keys() and srcport in self.allowed_ports[IPtup].keys()):
        log.debug("Port timeout: " + IPtup[0] + ':' + port)
        self.remove_port(IPtup, srcport, port)
    del(self.timers[ip_and_port][0])
    
  def remove_port(self, IPtup, srcport, port):
    try:
        self.allowed_ports[IPtup][srcport].remove(port)
    except KeyError:
        pass
    if(len(self.allowed_ports[IPtup][srcport]) == 0):
        del(self.allowed_ports[IPtup][srcport])
    if(len(self.allowed_ports[IPtup].keys())==0):
        del(self.allowed_ports[IPtup])