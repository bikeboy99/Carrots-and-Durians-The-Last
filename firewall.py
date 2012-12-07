from pox.core import core
from pox.lib.addresses import * 
from pox.lib.packet import *
from pox.lib.recoco.recoco import *
import re

# Get a logger
log = core.getLogger("fw")

class Firewall (object):
  """
  Firewall class.
  Extend this to implement some firewall functionality.
  Don't change the name or anything -- the eecore component
  expects it to be firewall.Firewall.
  """
  
  TIMEOUT = 10
  BASIC_PORTS = 1024
  
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
            if(IPtuple in self.allowed_ports.keys()):
                log("Duplicate FPT connection BLOCKED: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
                event.action.deny = True
            else:
                self.allowed_ports[IPtuple] = {}
                log.debug("Allowed FTPcmd connection: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
                self.mark_monitored(event, flow)
                event.action.forward = True
        else:
            log.debug("Allowed connection: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
            event.action.forward = True
        return
    elif IPtuple in self.allowed_ports.keys():
        for srcport in self.allowed_ports[IPtuple].keys():
            if(port in self.allowed_ports[IPtuple][srcport]):
                log.debug("Allowed FTP data connection to connect: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
                #remove once 1 TCP connection is made
                #cancel timer here??? maybe?
                self.allowed_ports[IPtuple][srcport].remove(port)
                if(len(self.allowed_ports[IPtuple][srcport]) == 0):
                    del(self.allowed_ports[IPtuple][srcport])
                if(len(self.allowed_ports[IPtuple].keys())==0):
                    del(self.allowed_ports[IPtuple])
                event.action.forward = True
                return
    else:
        event.action.deny = True
        log.debug("DENIED connection: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
        return

  def _handle_MonitorData (self, event, packet, reverse):
    #if(not reverse):
    #    IPStr = ip.dstip.toStr() + ',' + str(tcp.dstport) + ',' + ip.srcip.toStr() + ',' + str(tcp.srcport)
    #else:
    #    IPStr = ip.srcip.toStr() + ',' + str(tcp.srcport) + ',' + ip.dstip.toStr() + ',' + str(tcp.dstport)
    
    #if(IPStr in self.monitored_connections):     
    ip = packet.payload
    tcp = ip.payload
    data = tcp.payload
    #TODO: handle line split or line padded cases
    #handles padded case??
    data = data.strip()
    if(data[0:3] == '229'):
        data = data.split('|')
        port = data[len(data)-2]
        #not sure about reverse, not sure if IP will be formatted correctly
        if(reverse):
            IPtup = (ip.srcip.toStr(), ip.dstip.toStr())
        else:
            IPtup = (ip.dstip.toStr(), ip.srcip.toStr())
        self.open_port_with_timeout(port, IPtup, str(tcp.srcport), self.TIMEOUT)
        #self.monitored_connections.remove(IPStr)
    elif(data[0:3]  == '227'):
        data = data.split('(')
        csvs = data[len(data)-1].split(')')[0] 
        ip_and_port = csvs.split(',')
        IP = ip_and_port[0]+'.'+ip_and_port[1]+'.'+ip_and_port[2]+'.'+ip_and_port[3]
        if(reverse):
            IPtup = (IP, ip.dstip.toStr())
        else:
            IPtup = (IP, ip.srcip.toStr())
        port = str(int(ip_and_port[4])*256+int(ip_and_port[5]))
        self.open_port_with_timeout(port, IPtup, str(tcp.srcport), self.TIMEOUT)
    elif(data[0:3] == '226'):
        #close port before timeout
        if(reverse):
            IPtup = (ip.srcip.toStr(), ip.dstip.toStr())
        else:
            IPtup = (ip.dstip.toStr(), ip.srcip.toStr())
        try:
            del(self.allowed_ports[IPtup][str(tcp.srcport)])
        except KeyError:
            pass
        
  def open_port_with_timeout(self, port, IPtup, srcport, timeout):
    ip_and_ports = (IPtup, srcport,  port)
    log.debug("Opening port: " + IPtup[0] + ':' + port)
    try:
        if(self.timers[ip_and_ports]):
            selt.timers[ip_and_ports].cancel()
    except KeyError:
        pass
    if(not IPtup in self.allowed_ports.keys()):
        self.allowed_ports[IPtup] = {}
    if(not srcport in self.allowed_ports[IPtup].keys()):
        self.allowed_ports[IPtup][srcport] = set([])
    self.allowed_ports[IPtup][srcport].add(port)
    self.timers[ip_and_ports] = Timer(timeout, self.handle_timeout, args = [IPtup, srcport, port])
    
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
    ip_and_port = (IPtup, srcport, port)
    if(IPtup in self.allowed_ports.keys() and srcport in self.allowed_ports[IPtup].keys()):
        log.debug("Port timeout: " + IPtup[0] + ':' + port)
        self.allowed_ports[IPtup][srcport].remove(port)
        if(len(self.allowed_ports[IPtup][srcport]) == 0):
            del(self.allowed_ports[IPtup][srcport])
        if(len(self.allowed_ports[IPtup].keys())==0):
            del(self.allowed_ports[IPtup])
    del(self.timers[ip_and_port])