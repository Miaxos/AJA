# -*- coding: utf-8 -*-
import threading
import LayerPhy
import math
import random
from Tools.DebugOut import DebugOut
import time

class NetworkStackAlternative(object):

    def __init__(self, masterHost='127.0.0.1', baseport=10000, ownIdentifier='x', autoEnter=True):
        self.__debugOut=DebugOut()
        self.__applicationList=[]
        self.__sendDelay=0
        self.__layerDelay=0
        self.__layerPhy=LayerPhy.LayerPhy(ownIdentifier, upperLayerCallbackFunction=self.layer2_incomingPDU, masterHost=masterHost, baseport=baseport, autoEnter=autoEnter)
        # You may want to change the following part
        self.__ownIdentifier=ownIdentifier
        self.outgoingPacketStack=[]
        self.outgoingPacketStackLock=threading.Lock()
        

    def leaveNetwork(self):
        self.__layerPhy.API_leave()
        
    def enableGlobalDebug(self):
        self.__layerPhy.API_subscribeDebug()
        
    def configureDelay(self,sendDelay=None,layerDelay=None):
        if sendDelay!=None:
            self.__sendDelay=sendDelay
        if layerDelay!=None:
            self.__layerDelay=layerDelay

    # Do not change!
    # This is the application layer protocol part: Each application has its specific port
    # The application registers a callback function that is called when a packet arrives for that particular application
    def applicationAddCallback(self, applicationPort, callBack):
        self.__applicationList.append((applicationPort, callBack))

    # Do not change!
    # The application sends packets which are stored in a buffer before being submitted
    def applicationSend(self, destination, applicationPort, pdu):
        self.outgoingPacketStackLock.acquire()
        self.outgoingPacketStack.insert(0,(destination, applicationPort,pdu))
        self.outgoingPacketStackLock.release()


#############################################################################################################################################
#############################################################################################################################################

    # Please change: This sends the first TOKEN to the ring
    # In fact, sending a TOKEN requires the creation of a new thread
    def initiateToken(self):
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"Initiating TOKEN" )
        tokenThread=threading.Thread(target=self.application_layer_outgoingPDU, args=(True,))
        tokenThread.start()

    # Please adapt if required : This is the top layer that usually sends the data to the application
    # If pdu is None, the packet is not valid
    # forceToken determines that the return packet needs to be a TOKEN
    def application_layer_incomingPDU(self, forceToken, source, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: application_layer_in: received (%s) " % (self.__ownIdentifier,pdu))
        if pdu!=None:
            applicationPort=int.from_bytes(pdu[0:1],byteorder="little",signed=False)
            sdu=pdu[1:]

            # We deliver the SDU to the application that handles this message
            for (thisApplicationPort, thisApplication) in self.__applicationList:
                if thisApplicationPort==applicationPort:
                    thisApplication(source, applicationPort, sdu.decode('UTF-8'))
        
        # We dive back down into the network stack
        self.application_layer_outgoingPDU(forceToken)
                

    # Please adapt if required: This is the top layer that retrieves one element from the application layer 
    def application_layer_outgoingPDU(self, forceToken=False):
        time.sleep(self.__layerDelay)
        self.outgoingPacketStackLock.acquire()
        if len(self.outgoingPacketStack)==0 or forceToken:
            destination="X"
            applicationPort=20
            sdu="TOKEN"
        else:
            destination,applicationPort,sdu=self.outgoingPacketStack.pop()
        self.outgoingPacketStackLock.release()
        
        pdu=applicationPort.to_bytes(1,byteorder="little",signed=False)+sdu.encode("UTF-8")
        self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: application_layer_out: sending (%s) " % (self.__ownIdentifier,pdu))
        self.layer4_outgoingPDU(destination, applicationPort, pdu)

        
    # Please adapt!
    # Take care: The parameters of incoming (data packets arriving at the computer) and outgoing (data packets leaving from the computer)
    # should generally agree with one layer difference (i.e. here we treat the applicationPort, an identifier that knows which application
    # is asked to handle the traffic
    def layer4_incomingPDU(self, source, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: Layer4_in: Received (%s) from %s " % (self.__ownIdentifier,pdu, source))

    # Please adapt
    def layer4_outgoingPDU(self, destination, applicationPort, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: Layer4_out: Sending (%s) to %s " % (self.__ownIdentifier, pdu, destination))

    def layer3_incomingPDU(self, interface, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer3_in: tirage (%s) -> layer4_in\n" % (self.__ownIdentifier, pdu))

    # Please adapt
    def layer3_outgoingPDU(self, destination, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: Layer3_out: Sending out (%s) via interface %d " % (self.__ownIdentifier, pdu, 0))

    # Please adapt
    def layer2_incomingPDU(self, interface, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: Received (%s) on Interface %d " % (self.__ownIdentifier, pdu, interface))

        self.layer2_outgoingPDU(interface,pdu)

    def layer2_outgoingPDU(self, interface, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_out: Sending out (%s) via interface %d " % (self.__ownIdentifier, pdu, interface))
        if self.__sendDelay!=0:
            self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_out: Sleeping for %ds" % (self.__ownIdentifier,self.__sendDelay))
            time.sleep(self.__sendDelay)
        self.__layerPhy.API_sendData(interface, pdu)
