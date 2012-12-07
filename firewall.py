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
    if flow.dstport < self.BASIC_PORTS:
        event.action.forward = True
        log.debug("Allowed connection: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
        if(flow.dstport == 21):
            log.debug("FTPcmd connection marked for monitoring.  Data: " + packet.payload.payload.payload)
            self.mark_monitored(event, flow)
        return
    elif str(flow.dstport) in self.allowed_ports:
        log.debug("Allowed FTP data connection to connect.  Port: " + str(flow.dstport))
        #remove once 1 TCP connection is made
        #cancel timer here??? maybe?
        self.allowed_ports.remove(str(flow.dstport))
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
    if(data[0:4] == '229-'):
        data = data.split('|')
        if(len(data) == 5 and len(data[3]) > 3):
            if(self.timers[port]):
                selt.timers[port].cancel()
            port = data[3]
            self.open_port_with_timeout(port, self.TIMEOUT)
            #self.monitored_connections.remove(IPStr)
    elif(data[0:3] == '229'):
        data = data.split('|')
        port = data[3]
        self.open_port_with_timeout(port, self.TIMEOUT)
        #self.monitored_connections.remove(IPStr)
    
  def open_port_with_timeout(self, port, timeout):
    log.debug("Opening port: " + port)
    try:
        if(self.timers[port]):
            selt.timers[port].cancel()
    except KeyError:
        pass
    self.allowed_ports.add(port)
    self.timers[port] = Timer(timeout, self.handle_timeout, args = [port])
    
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
        
  def handle_timeout(self, port):
    log.debug("Port timeout: " + port)
    self.allowed_ports.remove(port)
    del(self.timers[port])   