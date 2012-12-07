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
    
    #set that contains ports allowed due to FTP requests
    self.allowed_ports = set([])
    
    log.debug("Firewall initialized.")

  def _handle_ConnectionIn (self, event, flow, packet):
    """
    New connection event handler.
    You can alter what happens with the connection by altering the
    action property of the event.
    """
    
    # Banned port
    ip_and_port = str(flow.dst) + ':' + str(flow.dstport)
    if flow.dstport < self.BASIC_PORTS:
        event.action.forward = True
        log.debug("Allowed connection: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
        if(flow.dstport == 21):
            log.debug("FTPcmd connection marked for monitoring.")
            self.mark_monitored(event, flow)
        return
    elif ip_and_port in self.allowed_ports:
        log.debug("Allowed FTP data connection to connect.  Port: " + ip_and_port)
        #remove once 1 TCP connection is made
        #cancel timer here??? maybe?
        self.allowed_ports.remove(ip_and_port)
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
        port = data[3]
        #not sure about reverse, not sure if IP will be formatted correctly
        if(reverse):
            IP = ip.srcip.toStr()
        else:
            IP = ip.dstip.toStr()
        self.open_port_with_timeout(port, IP, self.TIMEOUT)
        #self.monitored_connections.remove(IPStr)
    elif(data[0:3]  == '227'):
        data = data.split('(')
        csvs = data[len(data)-1].split(')')[0] 
        log.debug("Csv: " + '---'.join(csvs))
        ip_and_port = csvs.split(',')
        IP = ip_and_port[0]+'.'+ip_and_port[1]+'.'+ip_and_port[2]+'.'+ip_and_port[3]
        port = str(int(ip_and_port[4])*256+int(ip_and_port[5]))
        self.open_port_with_timeout(port, IP, self.TIMEOUT)
        
  def open_port_with_timeout(self, port, IP, timeout):
    ip_and_port = IP + ':' + port
    log.debug("Opening port: " + ip_and_port)
    try:
        if(self.timers[ip_and_port]):
            selt.timers[ip_and_port].cancel()
    except KeyError:
        pass
    self.allowed_ports.add(ip_and_port)
    self.timers[str(IP) + str(ip_and_port)] = Timer(timeout, self.handle_timeout, args = [ip_and_port])
    
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
        
  def handle_timeout(self, ip_and_port):
    if(ip_and_port in self.allowed_ports):
        log.debug("Port timeout: " + ip_and_port)
        self.allowed_ports.remove(ip_and_port)
    del(self.timers[ip_and_port])