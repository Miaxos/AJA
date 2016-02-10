# -*- coding: utf-8 -*-
'''
Physical network management
'''

from PhyCoordinator import PhyMaster
from Tools import DebugOut

class PhyNode(object):

    def __init__(self, connection, clientAddr):
        self.connection=connection
        self.clientAddr=clientAddr
        self.listenInterfacePorts=[0,0]
        self.sendInterfaceConfig=[("",0),("",0)]
        

class PhyNetwork(object):

    def __init__(self, ownIdentifier, baseport=10000, numberOfNodesPerRing=4):
        self.__ownIdentifier=ownIdentifier
        self.__networkList = [[]]
        self.baseport=baseport
        self.numberOfNodesPerRing=numberOfNodesPerRing
        self.__phyMaster=PhyMaster.PhyMaster(self,ownIdentifier)
        self.__debugOut=DebugOut.DebugOut()
                
    def API_dumpPhyNetworkState(self):
        for thisRing in self.__networkList:
            for thisNode in thisRing:
                self.__debugOut.debugOutLayer(self.__ownIdentifier,1,self.__debugOut.INFO,"Node : Connection %s : ClientAddr %s : ListenInterfacePorts: %s : SendInterfaceConfig : %s " % (thisNode.connection, thisNode.clientAddr,thisNode.listenInterfacePorts, thisNode.sendInterfaceConfig))
        

    def getRingLength(self, ringNumber):
        return len(self.__networkList[ringNumber])
    
    def addNode(self, connection, clientAddr):
        newNode=PhyNode(connection, clientAddr)
        
        ringNumber=0
        for thisRing in self.__networkList:
            if len(thisRing) < self.numberOfNodesPerRing:
                break
            ringNumber=ringNumber+1
            
        if len(thisRing) == self.numberOfNodesPerRing:
            self.__networkList.append([])
            thisRing=self.__networkList[-1]
        
        nodeNumber=len(thisRing)
        thisRing.append(newNode)
        
        return (newNode, ringNumber, nodeNumber)
    
    def delNode(self,ringNumber, nodeNumber):
        thisRing=self.__networkList[ringNumber]
        thisRing.pop(nodeNumber)
    
    def getNodeByIndex(self, ringNumber, nodeNumber):
        return self.__networkList[ringNumber][nodeNumber]
    
    def getNextNode(self,ringNumber,nodeNumber):
        thisRing=self.__networkList[ringNumber]
        # Check whether we are at a higher ringNumber, then the router node requires special rules
        if ringNumber > 0 and nodeNumber == len(thisRing)-1:
            lowerRingRouterNode=self.getLowerRingRouterNode(ringNumber)
            return (lowerRingRouterNode,1)
        else:
            nextNodeNumber=(nodeNumber+1) % len(thisRing)
            return (thisRing[nextNodeNumber],0)

    def getPreviousNode(self,ringNumber,nodeNumber):
        # Check whether we are at a higher ringNumber, then the router node requires special rules
        if ringNumber > 0 and nodeNumber == 0:
            lowerRingRouterNode=self.getLowerRingRouterNode(ringNumber)
            return (lowerRingRouterNode,1)
        else:
            thisRing=self.__networkList[ringNumber]
            previousNodeNumber=(nodeNumber+len(thisRing)-1) % len(thisRing)
            return (thisRing[previousNodeNumber],0)

    def getLowerRingRouterNode(self,ringNumber):
        if ringNumber > 0:
            return self.__networkList[ringNumber-1][-1]
        else:
            return None

    def getHigherRingRouterNode(self,ringNumber):
        if ringNumber<len(self.__networkList):
            return self.__networkList[ringNumber+1][0]
        else:
            return None
    
    def getNodeByConnection(self, connection):
        nodeFound=None
        for thisRing in self.__networkList:
            for thisNode in thisRing:
                if connection == thisNode.connection:
                    nodeFound=thisNode
                    break
            if nodeFound is not None:
                break
        
        return nodeFound 
    
    def getNodePositionByConnection(self, connection):
        nodeFound=None
        ringNumber=0
        for thisRing in self.__networkList:
            nodeNumber=0
            for thisNode in thisRing:
                if connection == thisNode.connection:
                    nodeFound=thisNode
                    break
                else:
                    nodeNumber=nodeNumber+1
            if nodeFound is not None:
                break
            else:
                ringNumber=ringNumber+1

        if nodeFound is None:
            return (-1, -1)
        else:
            return (ringNumber, nodeNumber)

    def getListenInterfacePort(self, interfaceNumber,ringNumber,nodeNumber):
        if interfaceNumber==0:
            return self.baseport+ringNumber*100+nodeNumber
        else:
            return self.baseport+ringNumber*100+nodeNumber+self.numberOfNodesPerRing
    
   
     
        