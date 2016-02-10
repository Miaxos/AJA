# -*- coding: utf-8 -*-
from PhyCoordinator.PhyNetwork import PhyNetwork
from Computer import Computer
import time
from Tools.DebugOut import DebugOut
from Tools.DebugGui import DebugGui

if __name__ == '__main__':
    
    # ============================================================================
    # This file opens a PhyMaster and  
    # a global DEBUG perspective.
    # 
    # It does not open a working computer. It is meant as a standalone server running 
    # until one or more mainComputer.py connect and form a ring. It will continue
    # running even if the computers connect and disconnect, so this is the most
    # general test case which requires that the network deals with missing TOKENs.  
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
    debugGui=DebugGui(ignoreComputer=["PhyMaster","Main"],layerSelection=[1,2,16,15,14,13,12,11],geometry="1800x1000+10+10")
    
    # We try to be the master first
    # If you want to have more nodes on a single ring, please change numberOfNodesPerRing
    __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Initiating PhyMaster")
    network=PhyNetwork(baseport=10000, numberOfNodesPerRing=4, ownIdentifier="PhyMaster")    
    __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Initiating PhyMaster done \n")

    __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Instanciation ordinateur pour acceder au deboggage")
    computer1=Computer(ownIdentifier="Z", masterHost='127.0.0.1', baseport=10000, autoEnter=False)
    computer1.enableGlobalDebug()
