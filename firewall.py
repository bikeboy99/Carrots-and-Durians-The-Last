from pox import core
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
    #v: set of allowed ports for these values
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
    IPtup = (str(flow.dst), str(flow.src))
    port = str(flow.dstport)
    if flow.dstport < self.BASIC_PORTS:
        event.action.forward = True
        if(flow.dstport == 21):
            log.debug("Allowed FTPcmd connection: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
            event.action.monitor_backward = True
        else:
            log.debug("Allowed connection: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
        return
    elif IPtup in self.allowed_ports.keys() and flow.dstport < self.FTP_PORTS:
        log.debug("IP with allowed ports: " + IPtup[0])
        log.debug("Allowed ports: " + ', '.join( self.allowed_ports[IPtup]))
        if(port in self.allowed_ports[IPtup]):
            log.debug("Allowed FTP data connection to connect: [" + str(flow.src) + ":" + str(flow.srcport) + "," + str(flow.dst) + ":" + str(flow.dstport) + "]")
            #remove once 1 TCP connection is made
            #cancel timer here. and delete timer.
            ip_and_port = (IPtup, str(flow.dstport))
            self.timers[ip_and_port][0].cancel()
            del(self.timers[ip_and_port][0])
            event.action.forward = True
            #port is no longer allowed if no more waiting timers for connections
            if(len(self.timers[ip_and_port]) == 0):
                self.remove_port(IPtup, port)
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
        srcport = str(tcp.srcport)
        
        if(reverse):
            IPtup = (ip.srcip.toStr(), ip.dstip.toStr())
        else:
            IPtup = (ip.dstip.toStr(), ip.srcip.toStr())
        
        try:            
            server_buffers = self.buffers[IPtup]
        except KeyError:
            self.buffers[IPtup] = {}
            server_buffers = self.buffers[IPtup]
        
        try:
            data = server_buffers[srcport] + data
        except KeyError:
            #first time initializing buffer
            server_buffers[srcport] = ''
            if(self.PRINT_BUFFERS):
                log.debug("Initializing Buffer for: " + IPtup[0])
        if(self.PRINT_BUFFERS):
            log.debug("Data: " + data)
            log.debug("Old Buffer: " + server_buffers[srcport])   
        
        #now split line based on newline  
        split = data.splitlines()
        if(self.PRINT_BUFFERS):
            log.debug("Split: " +  '---'.join(split))
        #if no EOL at end of string add it to buffer instead of processing now
        if(data != '' and data[-1] != '\n'):
            end = split[len(split)-1]
            server_buffers[srcport] = end
            #so end isn't processed, because we want it in buffer instead
            split = split[0:len(split)-1]
        #if there is a newline at the end of our data, clear our buffer for next time 
        elif(data[-1] == '\n'):
            server_buffers[srcport] = ''
        if(self.PRINT_BUFFERS):
            log.debug("New Buffer: " + server_buffers[srcport])
        
        port_227_regex = "\([0-9]{1,3},[0-9]{1,3},[0-9]{1,3},[0-9]{1,3},[0-9]{1,5},[0-9]{1,5}\)\.?$"
        port_229_regex = "\(\|\|\|[0-9]{4,5}\|\)\.?$"
       
        #for each individual FULL line in our data
        for line in split:
            try:
                if(len(line) > 3):
                    if(line[0:4] == '229 '):
                        try:
                            re_result = re.search(port_229_regex, line)
                            if re_result:
                                port = int(re_result.group(0).split("|")[3])
                                if port >= self.BASIC_PORTS and port < self.FTP_PORTS:
                                    self.open_port_with_timeout(str(port), IPtup, self.TIMEOUT)
                        except:
                            log.debug("Exception 229")
                            continue
                        
                    elif(line[0:4]  == '227 '):
                        try:
                            re_result = re.search(port_227_regex, line)
                            if re_result:
                                split_result = re_result.group(0).split('(')[1]
                                split_result = split_result.split(')')[0]
                                split_result = split_result.split(",")
                                
                                IP = split_result[0]+'.'+ split_result[1]+ '.' + split_result[2]+'.' + split_result[3]
                                if (reverse):
                                    IPtup = (IP, ip.dstip.toStr())
                                else:
                                    IPtup = (IP, ip.srcip.toStr())
                                port = int(split_result[4])*256+int(split_result[5])
                                if port >= self.BASIC_PORTS and port < self.FTP_PORTS:
                                    self.open_port_with_timeout(str(port), IPtup, self.TIMEOUT)
                        except:
                            log.debug("Exception 227")
                            continue
                        
            except:
                log.debug("IF YOU SEE THIS MESSAGE, BE VERY SCARED.  BE VERY FREAKING SCARED.  BECAUSE IT'S ALL ABOUT TO BE COMING DOWN")
                log.debug("WHY IS THIS COMING HERE")
                continue
    except:
        log.debug("IF YOU SEE THIS MESSAGE, BE VERY SCARED.  BE VERY FREAKING SCARED.  BECAUSE IT'S ALL ABOUT TO BE COMING DOWN")
        log.debug("IF YOU SEE THIS MESSAGE, BE VERY SCARED.  BE VERY FREAKING SCARED.  BECAUSE IT'S ALL ABOUT TO BE COMING DOWN!!!!!!!!!!")
        log.debug("IF YOU SEE THIS MESSAGE, BE VERY SCARED.  BE VERY FREAKING SCARED.  BECAUSE IT'S ALL ABOUT TO BE COMING DOWN!!!!!!!!!!!!!!!!!!!!!!!!!")
        pass
            
  def open_port_with_timeout(self, port, IPtup, timeout):
    ip_and_ports = (IPtup, port)
    log.debug("Opening port: " + IPtup[0] + ':' + port)

    if(not IPtup in self.allowed_ports.keys()):
        self.allowed_ports[IPtup] = set([])
    self.allowed_ports[IPtup].add(port)
    
    if(ip_and_ports not in self.timers.keys()):
        self.timers[ip_and_ports] = []
    self.timers[ip_and_ports].append(Timer(timeout, self.handle_timeout, args = [IPtup, port]))
        
  def handle_timeout(self, IPtup, port):
    ip_and_ports = (IPtup, port)
    if(IPtup in self.allowed_ports.keys()):
        log.debug("Port timeout: " + IPtup[0] + ':' + port)
        self.remove_port(IPtup, port)
    del(self.timers[ip_and_ports][0])
    
  def remove_port(self, IPtup, port):
    try:
        self.allowed_ports[IPtup].remove(port)
    except KeyError:
        pass
    if(len(self.allowed_ports[IPtup]) == 0):
        del(self.allowed_ports[IPtup])