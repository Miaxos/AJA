# -*- coding: utf-8 -*-
import socket
import threading
from Tools.TCPServer import TCPServer 

from Tools.DebugOut import DebugOut

class PhyMaster(object):
    '''
    classdocs
    '''

    def __init__(self, phyNetwork, ownIdentifier):
        self.__ownIdentifier=ownIdentifier
        self.__host='' # We are listening on any incoming connection
        self.__phyNetwork=phyNetwork
        self.__receivedMessage=threading.Condition()
        self.__debugOut=DebugOut(phyNetwork)
        self.__globalDebugHistory=[]
        self.__debugSubscribers=[]
        self.active=False
        self.__commandlist=[]
        try:
            self.__masterServer=TCPServer(host=self.__host, port=self.__phyNetwork.baseport-1, callBackReceive=self.__masterListen, callBackConnect=self.__masterConnect, callBackHandleSocketError=self.__masterSocketError)
            self.active=True
        except:
            self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PhyMaster : Master Server seems to be already running")

        if self.active:
            # This is the serialized dispatch thread
            self.__dispatchThread=threading.Thread(target=self.__dispatchCommands)
            self.__dispatchThread.start()


    def __waitForAcknowledge(self,connection):
        found=False
        while not found:
            index=0
            for (thisConnection,clientAddr,line) in self.__commandlist:
                if thisConnection == connection:
                    (command, separator, line)=line.partition(",")
                    (result, separator, line)=line.partition(",")
                    if command=="STATUS":
                        found=True
                        self.__commandlist.pop(index)
                        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PhyMaster %s - Waited for Acknowledge and got: %s %s" % (clientAddr, result, line))
                        if result=="ACK" :
                            result=True
                        else:
                            result=False
                index=index+1
            if not found:
                numberOfCommandsPriorToWait=len(self.__commandlist)
                self.__receivedMessage.wait(0.1)
                # Check for timeout
                if numberOfCommandsPriorToWait==len(self.__commandlist):
                    result=False
                    break
        return result
 
    def __nodeConnect(self, node, connectNode, clientAddr, listenPort, interfaceNumber):
        self.__masterServer.sendConnection(connectNode.connection,('CONNECT,%d,%s,%d\n' % (interfaceNumber,clientAddr[0],listenPort)))
        retval=False
        if not self.__waitForAcknowledge(connectNode.connection):
            self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"DEBUG: PhyMaster %s - connect for previous node %s failed" % (clientAddr,connectNode.clientAddr))
        else:
            connectNode.sendInterfaceConfig[interfaceNumber]=(clientAddr[0],listenPort)
            retval=True
        return retval

    def __nodeDisconnect(self, node, disconnectNode, interfaceNumber):
        # We can also safely disconnect the current node
        self.__masterServer.sendConnection(disconnectNode.connection,("DISCONNECT,%d\n" % interfaceNumber))
        retval=False
        if not self.__waitForAcknowledge(disconnectNode.connection):
            self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"DEBUG: PhyMaster %s - disconnect for current node %s failed" % (node.clientAddr,disconnectNode.clientAddr))
        else:
            disconnectNode.sendInterfaceConfig[interfaceNumber]=('',0)
            retval=True
            
        return retval
            
    def __nodeAddInterface(self, node, addInterfaceNode, interfaceNumber):
        (addInterfaceRingNumber, addInterfaceNodeNumber)=self.__phyNetwork.getNodePositionByConnection(addInterfaceNode.connection)
        listenPort=self.__phyNetwork.getListenInterfacePort(interfaceNumber,addInterfaceRingNumber, addInterfaceNodeNumber)
        acknowledge=False
        while not acknowledge:
            self.__masterServer.sendConnection(addInterfaceNode.connection,("ADDINTERFACE,%d,%d\n" % (interfaceNumber,listenPort)))
            acknowledge=self.__waitForAcknowledge(addInterfaceNode.connection)
            if not acknowledge:
                listenPort=listenPort+1
        addInterfaceNode.listenInterfacePorts[interfaceNumber]=listenPort
        return True

    def __nodeDelInterface(self, node, delInterfaceNode, interfaceNumber):
        self.__masterServer.sendConnection(delInterfaceNode.connection,("DELINTERFACE,%d\n"% interfaceNumber))
        retval=False
        if not self.__waitForAcknowledge(delInterfaceNode.connection):
            self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"DEBUG: PhyMaster %s - delinterface for current node %s failed" % (node.clientAddr,delInterfaceNode.clientAddr))
        else:
            delInterfaceNode.listenInterfacePorts[interfaceNumber]=0
            retval=True
        return retval
    
    def __handleLeave(self, connection, clientAddr, assumeDisconnect=False):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"LEAVE : Entering configuration section")
        thisNode=self.__phyNetwork.getNodeByConnection(connection)
        (ringNumber, nodeNumber)=self.__phyNetwork.getNodePositionByConnection(connection)
        (previousNode, previousInterfaceNumber)=self.__phyNetwork.getPreviousNode(ringNumber,nodeNumber)
        (nextNode, nextInterfaceNumber)=self.__phyNetwork.getNextNode(ringNumber,nodeNumber)
        ringHandoverNode=None
        if thisNode is None:
            self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"DEBUG: PhyMaster %s received LEAVE request from unknown client" % (clientAddr,))
        else:  
            # We first treat interface 0 : Reconnect previous and next node
            # Assume, B is to be removed from the middle of A and C
            
            # We can disconnect the previous node in any case
            self.__nodeDisconnect(thisNode, previousNode, previousInterfaceNumber)

            # We can also safely disconnect the current node
            if not assumeDisconnect:
                self.__nodeDisconnect(thisNode, thisNode, 0)
                
            # We shutdown the current interface 0 which should no longer be connected in any case (even if immediate loop)
            if not assumeDisconnect:
                self.__nodeDelInterface(thisNode, thisNode, 0)

            # Check whether we are the last node on the ring
            if ringNumber > 0 and self.__phyNetwork.getRingLength(ringNumber)==1: 
                # then the previousNode (and the nextNode should be the connection to the lower ring
                if previousInterfaceNumber != 1:
                    self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"DEBUG: PhyMaster %s - Something is strange, only one node left but previous is not on interface 1" % (clientAddr,))
                else:
                    ringHandoverNode=previousNode
                    self.__nodeDelInterface(thisNode, previousNode, previousInterfaceNumber)
                        
            else: # This is the normal case, we have at least 2 nodes left
                self.__nodeConnect(thisNode, previousNode, nextNode.clientAddr, nextNode.listenInterfacePorts[nextInterfaceNumber], previousInterfaceNumber)
                      
            # Check whether we are the uplink node
            if thisNode.listenInterfacePorts[1]!=0:
                if self.__phyNetwork.getRingLength(ringNumber)>1:
                    if previousNode.listenInterfacePorts[1]!=0:
                        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"DEBUG: PhyMaster %s - Something is strange, there is a previous node which is an uplink but the current is uplink, too" % (clientAddr,))
                    else:
                        # We need to do a Ring Handover here: Imagine, we have D2 -> D1 -> A2 with D1 being in Ring 1, the rest in Ring 2
                        # Then we want to handover from D1 to C1 because we remove D1
                        if ringHandoverNode == None:
                            ringHandoverNode=previousNode
                        (handoverRingNumber, handoverNodeNumber)=self.__phyNetwork.getNodePositionByConnection(ringHandoverNode.connection)
                        
                        # We first enable the interface 1 on C1
                        self.__nodeAddInterface(thisNode, ringHandoverNode, 1)
                        
                        # Now we need to hand over the upper ring to the previous Node
                        predecessorNode=self.__phyNetwork.getNodeByIndex(ringNumber+1,-1)
                        sucessorNode=self.__phyNetwork.getNodeByIndex(ringNumber+1,0)
                        
                        # Then we connect D2 to C1
                        self.__nodeDisconnect(thisNode, predecessorNode, 0)
                        self.__nodeConnect(thisNode, predecessorNode, ringHandoverNode.clientAddr, ringHandoverNode.listenInterfacePorts[1], 0)
                        
                        # Now we connect C1 to A2
                        self.__nodeDisconnect(thisNode, thisNode, 1)
                        self.__nodeConnect(thisNode, ringHandoverNode, sucessorNode.clientAddr, sucessorNode.listenInterfacePorts[0], 1)
                        
                
                        
        self.__phyNetwork.delNode(ringNumber,nodeNumber)
        self.__phyNetwork.API_dumpPhyNetworkState()
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"LEAVE : Leaving configuration section")

    def __handleEnter(self, connection, clientAddr):
        self.__phyNetwork.addNode(connection, clientAddr)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"ENTER : Entering configuration section")
        thisNode=self.__phyNetwork.getNodeByConnection(connection)
        if thisNode is None:
            self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"DEBUG: PhyMaster %s received ENTER request from unknown client" % (clientAddr,)) 
        else:
            (ringNumber, nodeNumber)=self.__phyNetwork.getNodePositionByConnection(connection)
            # If this is the first node of a new Ring, we need to connect it downwards by enabling interface 1 of the lowerRing Node
            if nodeNumber == 0 and ringNumber > 0:
                lowerRingRouterNode=self.__phyNetwork.getLowerRingRouterNode(ringNumber)
                (lowerRingNumber, lowerRingNodeNumber)=self.__phyNetwork.getNodePositionByConnection(lowerRingRouterNode.connection)
                self.__nodeAddInterface(thisNode, lowerRingRouterNode, 1)
                
            # Let's imagine we want to insert B between A and C
            self.__nodeAddInterface(thisNode, thisNode, 0)

            (previousNode, previousInterfaceNumber)=self.__phyNetwork.getPreviousNode(ringNumber,nodeNumber)
            # We are disconnecting A from C
            self.__nodeDisconnect(thisNode, previousNode, previousInterfaceNumber)
       
            # We are connecting A to B
            self.__nodeConnect(thisNode, previousNode, clientAddr, thisNode.listenInterfacePorts[0], previousInterfaceNumber)
    
            # We are connecting B to C
            (nextNode, nextInterfaceNumber)=self.__phyNetwork.getNextNode(ringNumber,nodeNumber)
            
            self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"Trying to connect %s %d " % (nextNode.clientAddr[0],nextNode.listenInterfacePorts[0]))
            
            self.__nodeConnect(thisNode, thisNode, nextNode.clientAddr, nextNode.listenInterfacePorts[nextInterfaceNumber], 0)
            
        self.__phyNetwork.API_dumpPhyNetworkState()
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"ENTER : Leaving configuration section")
 
    def __handleDebugMsg(self,connection, clientAddr, line):
        self.__globalDebugHistory.append(line)
        for (sendConnection, sendClientAddr) in self.__debugSubscribers:
            try:
                self.__masterServer.sendConnection(sendConnection,("DEBUGMSG,"+line))
            except socket.error as msg:
                print("HandleDebugMsg - Exception caught: ",msg)
                self.__debugSubscribers.remove((sendConnection, sendClientAddr))
        
    
    def __handleSubscribeDebug(self,connection, clientAddr):
        subscribeOk=True
        for line in self.__globalDebugHistory:
            try:
                self.__masterServer.sendConnection(connection,("DEBUGMSG,"+line))
            except socket.error as msg:
                print("HandleDebugMsg - Exception caught: ",msg)
                subscribeOk=False
        if subscribeOk:
            self.__debugSubscribers.append((connection, clientAddr))
    
    def __dispatchCommands(self):
        while True:
            self.__receivedMessage.acquire()
            while len(self.__commandlist)>0:
                (connection,clientAddr,thisCommand)=self.__commandlist.pop(0)
                (command, separator, line)=thisCommand.partition(",")
                if command == "ENTER":
                    self.__handleEnter(connection, clientAddr)
                elif command == "LEAVE":
                    self.__handleLeave(connection, clientAddr)
                elif command == "DEBUGMSG":
                    self.__handleDebugMsg(connection, clientAddr, line)
                elif command == "SUBSCRIBEDEBUG":
                    self.__handleSubscribeDebug(connection, clientAddr)
                else:
                    self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"DEBUG: PhyMaster %s - Unknown Command %s" % (clientAddr,line))
            self.__receivedMessage.wait()
            

       

    def __masterListen(self, tcpServer, connection, clientAddr, data):
        self.__receivedMessage.acquire()
        while data:
            (line, separator, data)=data.partition("\n")
#            self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"DEBUG: PhyMaster %s - received %s" % (clientAddr,line))
            self.__commandlist.append((connection,clientAddr,line))
            self.__receivedMessage.notify()
        self.__receivedMessage.release()
  

    def __masterConnect(self, tcpServer, connection, clientAddr):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PhyMaster %s - Incoming connection" % (clientAddr,))
        
    def __masterSocketError(self,tcpServer, connection, clientAddr):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"PhyMaster %s - Received SocketError assuming disconnect" % (clientAddr,))
        self.__receivedMessage.acquire()
        self.__handleLeave(connection, clientAddr, True)
        self.__receivedMessage.release()
        
        
    
        

        