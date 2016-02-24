# -*- coding: utf-8 -*-
#test
from PhyCoordinator.PhyNetwork import PhyNetwork
from Computer import Computer
import time
from Tools.DebugOut import DebugOut
from Tools.DebugGui import DebugGui

if __name__ == '__main__':

    # ============================================================================
    # This file opens a central coordinating server (PhyMaster), 
    # at least two computers (with associated services),
    # a global DEBUG perspective,
    # and initiates a TOKEN
    # It is meant as a generic test framework for usage by one group
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
      
    # If you are using MacOS, the tkinter needs to run in the main thread
    # We could put the setup into another thread that would liberate the main thread thus, this is a workaround for the moment
    macosTkinterWorkaround=True

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
    debugGui=DebugGui(ignoreComputer=["PhyMaster","Main"],layerSelection=[1,2,16,15,14,13,12,11],geometry="1800x1000+10+10",macosTkinterWorkaround=macosTkinterWorkaround)
    
    # This should be outdated
    # __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Attention : les messages ne s'affichent pas toujours de façon séquentielle !")
    # __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"=> il faut donc souvent les ré-ordonner.\n")
    
    # We try to be the master first
    # If you want to have more nodes on a single ring, please change numberOfNodesPerRing
    # We remember the masterHostIp for using it with the "computers" later
    # Take care: If you want to have a network that spans multiple PCs, you need to specify the external IP here instead of localhost (127.0.0.1)
    masterHostIp='127.0.0.1'
    __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Initiating PhyMaster")
    network=PhyNetwork(baseport=10000, numberOfNodesPerRing=4, ownIdentifier="PhyMaster")
    __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Initiating PhyMaster done \n")

    # We are initiating one computer
    __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Instanciation computer 1")
    computer1=Computer(ownIdentifier="A", masterHost=masterHostIp, baseport=10000,statusUpdateSeconds=10)
    # Get the global debug messages from the server for the graphical interface (this shall only be done for one computer)
    computer1.enableGlobalDebug()
    # Configure the delay in each layer and before sending the packet out of the computer (for debugging)
    computer1.debugConfigureNetworkstackDelay(sendDelay=3,layerDelay=3)
    
    __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Instanciation computer 2")
    computer2=Computer(ownIdentifier="B", masterHost=masterHostIp, baseport=10000,statusUpdateSeconds=10)
    computer2.debugConfigureNetworkstackDelay(sendDelay=3,layerDelay=3)

    # We may want to have a third computer somewhen
    # In this case, we may even use the alternative network stack (networkStackNumber=1) which may come in handy to combine two implementations in one trial
    if False:
        __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Instanciation computer 3")
        if False:
            computer3=Computer(ownIdentifier="C", masterHost=masterHostIp, baseport=10000, networkStackNumber=0)
        else:
            computer3=Computer(ownIdentifier="C", masterHost=masterHostIp, baseport=10000, networkStackNumber=1)
        computer3.debugConfigureNetworkstackDelay(sendDelay=3,layerDelay=0)
    
    # Waiting three seconds to allow for the connections on the PHY Layer
    time.sleep(3)

    # Start sending some messages from computer 'A' to computer 'B'
    __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Starting some message from A to B")
    computer1.appMessageSend(destinationIdentifier="B", numberOfMessages=5)
    
    # Start sending some messages from computer 'B' to computer 'A'
    __debugOut.debugOutSource("Main",__debugOut.srcComputer,__debugOut.INFO,"Starting some message from B to A")
    computer2.appMessageSend(destinationIdentifier="A", numberOfMessages=5)
    
    time.sleep(2)

    # Computer 1 initiates the TOKEN manually in this protocol
    computer1.initiateToken()
    print("Token sent")
    # We may want to have this third computer leave the network after some time
    if False:
        time.sleep(10)
        computer3.stopComputer()

    if macosTkinterWorkaround:
        debugGui.launch()
