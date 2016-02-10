# -*- coding: utf-8 -*-
'''
This is the virtualized physical layer of the network's RING architecture
The RING is modeled by using TCP __connections on an Ethernet/IP based network
TCP Ports are used to identify individual machines (NODES).

Out-of-band CONTROL __connection:
The first RING member (MASTER) establishes a CONTROL __connection for all existing and future NODES on port 9999.
If port 9999 is occupied, it shall be assumed that there is already a MASTER listening.
In this case, a CONTROL __connection shall be established with the MASTER on port 9999 asking for the ports to use.

RING topology:
By default, the first RING member (MASTER) listens for RING traffic on port 10000 (incoming traffic, RING input) and sends to a machine that listens on port 10001 (RING output)
By default, the second RING member listens for RING traffic on port 10001 (incoming traffic, RING input) and sends to a machine that listens on port 10002 (RING output)
etc.
If a port is not available (already occupied by another program), that port number is skipped.

Each RING contains a maximum of 4 NODES.
By default, the first RING uses TCP ports 10000-10003, the second RING uses TCP ports 10100-10103, etc.
The last RING member closes the RING, i.e. it __connects to the first NODE of his RING, i.e. to TCP port 10x00.

Any change in the RING topology is coordinated by the MASTER.

A maximum of 10 RINGS shall coexist.

One NODE can be __connected to one or to two networks.
Corresponding INTERFACES are created on the fly.

All 1..40 NODES have a permanent __connection established to the MASTER node on port 9999, reacting on PHY_CONFIGURATION messages as requested.
The PHY_CONFIGURATION messages are transmitted only out-of-band on the port 9999 of the MASTER.
The PHY_CONFIGURATION messages are clear text messages with fields separated by a comma (',').
They must contain a MESSAGE keyword, and mandatory or optional parameters as indicated by the PHY_CONFIGURATION message list.
All integer values are converted to string values prior to sending.

The following PHY_CONFIGURATION messages are defined:

ORIGIN : MESSAGE  : Parameters              : Description
NODE   : ENTER    : none                    : Request of a node to be entered in any RING, answered with __addInterface
NODE   : LEAVE    : none                    : Request of a node to leave the RING, answered with __delInterface 
MASTER : __addInterface : INTERFACENUMBER,LISTENPORT : Request of the MASTER to the NODE to add an INTERFACE with the specified LISTENPORT, answered with STATUS
MASTER : __delInterface : INTERFACENUMBER             : Request to remove the specified INTERFACE 
MASTER : __connect : INTERFACENUMBER,IP,SENDPORT : Request of the MASTER to the NODE to __connect to the given IP,SENDPORT, answered with STATUS
MASTER : __disconnect : INTERFACENUMBER : Request of the MASTER to the NODE to detach from current IP,SENDPORT, answered with STATUS
NODE   : STATUS : ACKNOWLEDGEMENT, MESSAGE           : NODE provides information whether the requested operation was successfull (ACKNOWLEDGEMENT = "ACK") or not (ACKNOWLEDGEMENT = "FAILURE"), an additional, optional error message may be provided 
NODE   : SUBSCRIBEDEBUG : none                : Request to receive DEBUG messages
NODE   : DEBUGMSG : DEBUGSTRING                : Debug message sent to master for distribution
MASTER : DEBUGMSG : DEBUGSTRING                : Debug message sent distributed by master

INTERFACENUMBER : integer : 0 or 1
LISTENPORT : integer : 10000-10999
SENDPORT : integer : 10000-10999
ACKNOWLEDGEMENT: string : "ACK" or "NACK"

'''

import socket
import time
import threading

from PhyCoordinator.PhyMaster import PhyMaster
from Tools.TCPServer import TCPServer
from Tools.TCPClient import TCPClient
from Tools.DebugOut import DebugOut

class LayerPhy(object):
    '''
    classdocs
    '''


    def __init__(self, ownIdentifier,upperLayerCallbackFunction, masterHost='127.0.0.1', baseport=10000, autoEnter=True):
        '''
        Constructor
        '''
        self.__ownIdentifier=ownIdentifier
        self.__masterHost=masterHost
        self.__controlPort=baseport-1
        
        self.__interfaceSendPort=[0, 0]
        self.__interfaceRecvPort=[0, 0]
        
        self.__incomingTcpServer=[None, None]
        self.__outgoingTcpClient=[None, None]
            
        self.__callLinkLayer=upperLayerCallbackFunction
        
        self.__debugOut=DebugOut()
        self.__openControl_connection();
        if autoEnter:
            self.API_enter()
        
    def API_enter(self):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"Sending ENTER")
        self.controlTcpClient.send("ENTER\n");
        
    def API_leave(self):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"Sending LEAVE")
        self.controlTcpClient.send("LEAVE\n");

    def API_sendData(self, interfaceNumber=0, data=""):
        if self.__outgoingTcpClient[interfaceNumber] is not None:
            self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY - PhysicalLayer, Interface %d, sending %s" % (interfaceNumber, data))
            self.__outgoingTcpClient[interfaceNumber].sendBytes(data)  
            
    def API_subscribeDebug(self):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"Sending SUBSCRIBEDEBUG")
        self.controlTcpClient.send("SUBSCRIBEDEBUG\n");
        self.__debugOut.addLocalListenCallback(self.__sendDebugMsg)
        
    def __sendDebugMsg(self,eventTime,identifier,source,level,data):
        message="DEBUGMSG,%.6f,%s,%s,%s,%s" % (eventTime,identifier,source,level,data)
        self.controlTcpClient.send(message)

        
    def __handleDebugMsg(self,line):
        (eventTime, separator, line)=line.partition(",")
        eventTime=float(eventTime)
        (identifier, separator, line)=line.partition(",")
        (source, separator, line)=line.partition(",")
        source=int(source)
        (level, separator, line)=line.partition(",")
        level=int(level)
        self.__debugOut.globaldebugOutSource(eventTime,identifier,source,level,line)

    def __listenControl_connection(self, tcpClient, __connection, clientAddr, data):
        while data:
            (line, separator, data)=data.partition("\n")

            (command, separator, line)=line.partition(",")
            if command == "ADDINTERFACE":
                self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY %s - __listenControl_connection - received %s" % (clientAddr,line))
                (interfacenumber, separator, line)=line.partition(",")
                (listenport, separator, line)=line.partition(",")
                self.__addInterface(int(interfacenumber), int(listenport))
                self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY %s done __addInterface" % (clientAddr,))
            elif command == "DELINTERFACE":
                self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY %s - __listenControl_connection - received %s" % (clientAddr,line))
                (interfacenumber, separator, line)=line.partition(",")
                self.__delInterface(int(interfacenumber))
            elif command == "CONNECT":
                self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY %s - __listenControl_connection - received %s" % (clientAddr,line))
                (interfacenumber, separator, line)=line.partition(",")
                (ipAddress, separator, line)=line.partition(",")
                (listenport, separator, line)=line.partition(",")
                self.__connect(int(interfacenumber), ipAddress, int(listenport))
            elif command == "DISCONNECT":
                self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY %s - __listenControl_connection - received %s" % (clientAddr,line))
                (interfacenumber, separator, line)=line.partition(",")
                self.__disconnect(int(interfacenumber))
            elif command == "DEBUGMSG":
                self.__handleDebugMsg(line)
            else:
                self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY %s - listenControl_connection - Received unknown command %s." % (clientAddr,command))      
            
            
    def __openControl_connection(self):
        self.controlTcpClient= TCPClient(host=self.__masterHost, port=self.__controlPort, callBackReceive=self.__listenControl_connection)
        
    def __incomingData_connectionInterface0(self, tcpServer, __connection, clientAddr, data):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY %s - ListenData_connection on interface 0 received %s" % (clientAddr,data))
        self.__callLinkLayer(0,data)
            
    def __incomingData_connectionInterface1(self, tcpServer, __connection, clientAddr, data):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY %s - ListenData_connection on interface 1 received %s" % (clientAddr,data))
        self.__callLinkLayer(1,data)

    def __sendControl(self,data):
        self.controlTcpClient.send(data)
            
    def __addInterface(self, interfaceNumber=0, listenport=0):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY - Adding interface number %d with listenport %d" % (interfaceNumber, listenport))
        
        if self.__incomingTcpServer[interfaceNumber] is None:
            self.__interfaceRecvPort[interfaceNumber]=listenport
            if interfaceNumber==0:
                self.__incomingTcpServer[0]=TCPServer(host='',port=self.__interfaceRecvPort[0],callBackReceiveBytes=self.__incomingData_connectionInterface0)
            else:
                self.__incomingTcpServer[1]=TCPServer(host='',port=self.__interfaceRecvPort[1],callBackReceiveBytes=self.__incomingData_connectionInterface1)
            self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,'PHY - Tried to add interface, isServing is : %d' % self.__incomingTcpServer[interfaceNumber].isServing())
            if self.__incomingTcpServer[interfaceNumber].isServing():
                self.__sendControl("STATUS,ACK\n")
            else:
                self.__sendControl("STATUS,NACK,Interface open failed\n")
                self.__incomingTcpServer[interfaceNumber]=None
        else:
            self.__sendControl("STATUS,NACK,Interface is already __connected\n")
    
    def __delInterface(self, interfaceNumber):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"Removing interface number %d with listenport %d" % (interfaceNumber, self.__interfaceRecvPort[interfaceNumber]))
        if self.__incomingTcpServer[interfaceNumber] is None:
            self.__sendControl("STATUS,NACK,Interface is not active\n")
        else:
            self.__incomingTcpServer[interfaceNumber].stopServer()
            self.__incomingTcpServer[interfaceNumber]=None
            self.__sendControl("STATUS,ACK\n")
        
    def __connect(self, interfaceNumber=0, ipAddress="127.0.0.1",sendport=0):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY - __connecting interface %d to ip %s port %d" % (interfaceNumber, ipAddress, sendport))
        if self.__outgoingTcpClient[interfaceNumber] is None:
            self.__interfaceSendPort[interfaceNumber]=sendport
            self.__outgoingTcpClient[interfaceNumber]=TCPClient(host=ipAddress,port=self.__interfaceSendPort[interfaceNumber],callBackReceiveBytes=None)
            if self.__outgoingTcpClient[interfaceNumber].isConnected():
                self.__sendControl("STATUS,ACK\n")
            else:
                self.__sendControl("STATUS,NACK,Interface open failed\n")
        else:
            self.__sendControl("STATUS,NACK,Interface is already __connected\n")
    
        
    def __disconnect(self, interfaceNumber=0):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PHY - disconnecting interface %d from port %d" % (interfaceNumber, self.__interfaceSendPort[interfaceNumber]))
        if self.__outgoingTcpClient[interfaceNumber] is None:
            self.__sendControl("STATUS,NACK,Interface is not __connected\n")
        else:
            self.__outgoingTcpClient[interfaceNumber].stopClient()
            self.__outgoingTcpClient[interfaceNumber]=None 
            self.__sendControl("STATUS,ACK\n")
    
        
        
        
        