# -*- coding: utf-8 -*-

from PhyCoordinator.PhyNetwork import PhyNetwork
from Computer import Computer
import time
from Tools.DebugOut import DebugOut
from Tools.DebugGui import DebugGui
import os


if __name__ == '__main__':

    # ============================================================================
    # This file opens a computer and  
    # a global DEBUG perspective.
    # 
    # It is meant to connect an additional computer (potentially 
    # with a different network protocol implementation) to an existing PhyMaster
    # You may change the parameter of masterHost in order to connect to a remote PhyMaster
    # ============================================================================

    # We initialize here the debugging framework:
    # Each part of the computer has a debug source identifier
    # 0 is reserved for internal communication
    # 1 Is for general computer messages
    # 2 is for applications
    # 11 or layer=1 is used for the Physical Network Layer
    # 12 or layer=2 is used for the first network layer that is up to you to implement
    #
    # Various DebugLevels have been predefined, notably NONE, ERROR, WARNING, INFO, ALL (see Tools/DebugOut for more information)
      
    __debugOut=DebugOut()

    __debugOut.setDebugLevelForSource(__debugOut.srcComputer,       __debugOut.NONE)
    __debugOut.setDebugLevelForSource(__debugOut.srcApplication,    __debugOut.NONE)
    __debugOut.setDebugLevelForLayer(1, __debugOut.WARNING)
    # __debugOut.setDebugLevelForLayer(1, __debugOut.INFO)
    __debugOut.setDebugLevelForLayer(2, __debugOut.INFO)
    __debugOut.setDebugLevelForLayer(3, __debugOut.INFO)
    __debugOut.setDebugLevelForLayer(4, __debugOut.INFO)
    __debugOut.setDebugLevelForLayer(5, __debugOut.INFO)
    __debugOut.setDebugLevelForLayer(6, __debugOut.INFO)
    
    # This starts the graphical user interface
    # Computers (Nodes) are added automatically unless contained in ignoreComputers
    # The layerSelection determines the layers that are displayed graphically
    masterHostIp='127.0.0.1'
    debugGui=DebugGui(ignoreComputer=["PhyMaster","Main"],layerSelection=[1,2,16,15,14,13,12,11])
    
    __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Instanciation computer 1")
    computer1=Computer(ownIdentifier="C", masterHost=masterHostIp, baseport=10000,statusUpdateSeconds=10)
    computer1.debugConfigureNetworkstackDelay(sendDelay=3,layerDelay=1)
    computer1.enableGlobalDebug()
    
    time.sleep(3)
    
    if False:
        computer1.initiateToken()
    
#    time.sleep(10)
#    os._exit(0)
    
