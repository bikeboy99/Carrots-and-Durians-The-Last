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
  
  BASIC_PORTS = 1024
  
  def __init__(self):
    """
    Constructor.
    Put your initialization code here.
    """
    
    #dictionary to hold all the monitoring data for the connections
    #K: csv of: ext.IP, external port, internal IP, internal port
    #V: Timer
    self.timers = {}
    
    #set that contains valid connections as csv of ext.IP, external port, internal ip, internal port
    self.monitored_connections = set([])
    
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
    if flow.dstport < BASIC_PORTS:
        event.action.forward = True
        if(flow.dstport == 21):
            log.debug("FTP cmd connection in.  Data: \n" + packet.payload.payload.payload)
            #mark it for monitoring, handle reset of timers and monitored connection if its a duplicate connection.
            self.mark_monitored(event, flow, deferred)
        return
    elif flow.dstport in self.allowed_ports:
        self.allowed_ports.remove(flow.dstport)
        event.action.forward = True
        return
    else:
        event.action.deny = True
        log.debug("DENIED connection [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]" )
        return

  def _handle_MonitorData (self, event, packet, reverse):
    ip = packet.payload
    tcp = ip.payload
    data = tcp.payload
    


  def mark_monitored(self, event, flow, deferred):
    # Mark to monitor data
        #Treating destination as external... is this always true?
        IPStr = flow.dst.toStr() + ',' + str(flow.dstport) + ',' + flow.src.toStr() + ',' + str(flow.srcport)
        log.debug("Monitoring connection: " + IPStr)
        #Same conneciton already exists!
        if IPStr in self.monitored_connections:
            if(self.timers[IPStr] != None):
                self.timers[IPStr].cancel()
            log.debug("Old connection still exists.  Resetting options.")
            #TODO: handle any port shenannigans that must be done here
        else:
            self.monitored_connections.add(IPStr)
        #new tuple to hold data snippets and timer
        if deferred:
            data = Timer(self.TIMEOUT, self.handle_timeout, args = [IPStr])
        self.timers[IPStr] = data
        
        #monitor this connection in both directions
        event.action.monitor_forward = True
        event.action.monitor_backward = True
        
  def handle_timeout(self, IPstr):
    log.debug("Connection timeout: " + IPStr)
    if IPStr in self.monitored_connections:
        self.monitored_connections.remove(IPStr)
        del(self.timers[IPStr]) 
        #TODO: close ports and stuff!   