# -*- coding: utf-8 -*-
import threading
import LayerPhy
import math
import random
from Tools.DebugOut import DebugOut
import time

class NetworkStack(object):

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
        # Layer 5 dans l'application (Le premier element du paquet se trouve dedans)
        # Les données sont toutes seules pour le moment.
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
        # Layer 5 dans l'application (Le premier element du paquet se trouve dedans)
        # On récupère les infos de l'application, dont le type de paquet qu'on balance, pour qui, avec les données.
        time.sleep(self.__layerDelay)
        self.outgoingPacketStackLock.acquire()
        if len(self.outgoingPacketStack)==0 or forceToken:
            destination= 15
            applicationPort=20
            sdu="TOKEN"
        else:
            destination,applicationPort, sdu=self.outgoingPacketStack.pop()
        self.outgoingPacketStackLock.release()
        # On doit mettre en place le checksum !

        # On va avoir une structure genre pdu= applicationPort.to_bytes(1,byteorder="little",signed=False)+sdu.encode("UTF-8")
        
        # Data
        pdu=sdu.encode("UTF-8")
        
        #Dest
        pdu=destination.to_bytes(1,byteorder="little",signed=False)+pdu

        # Checksum
        pdu=HashageAJA(pdu).to_bytes(2,byteorder="little")+pdu
        
        # Protocol
        pdu=applicationPort.to_bytes(1,byteorder="little",signed=False)+pdu
        self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: application_layer_out: sending (%s) " % (self.__ownIdentifier,pdu))
        self.layer4_outgoingPDU(destination, applicationPort, pdu)

# --------- ENCAPSULAGE --------


    def layer7_outgoingPDU(self, destination, source, type, pdu, TTL=255):
        # encapsulage du checksum
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,7,self.__debugOut.INFO,"%s: Layer7_out: Sending (%s) to %s " % (self.__ownIdentifier, pdu, destination))
        pdu=HashageAJA(pdu).to_bytes(2,byteorder="little")+pdu
        self.layer6_outgoingPDU(destination, source, pdu, TTL)

    def layer6_outgoingPDU(self, destination, source, type, pdu, TTL=255):
        # encapsulage source
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,6,self.__debugOut.INFO,"%s: Layer6_out: Sending (%s) to %s " % (self.__ownIdentifier, pdu, destination))
        pdu=source.to_bytes(1,byteorder="little",signed=False)+pdu
        self.layer5_outgoingPDU(destination, pdu, TTL)

    def layer5_outgoingPDU(self, destination, pdu, TTL=255):
        # encapsulage destination
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: Layer5_out: Sending (%s) to %s " % (self.__ownIdentifier, pdu, destination))
        pdu=destination.to_bytes(1,byteorder="little")+pdu
        self.layer4_outgoingPDU(type, pdu, TTL)

    def layer4_outgoingPDU(self, type, pdu, TTL=255):
        # encapsulage TTL
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: Layer4_out: Sending (%s)" % (self.__ownIdentifier, pdu))
        pdu=TTL.to_bytes(1,byteorder="little")+pdu
        self.layer3_outgoingPDU(type, pdu)

    def layer3_outgoingPDU(self, type, pdu):
        # encapsulage Type
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: Layer3_out: Sending (%s)" % (self.__ownIdentifier, pdu))
        pdu=type.to_bytes(1,byteorder="little")+pdu
        self.layer2_outgoingPDU(pdu)

    #4 -> TTL

    def layer2_outgoingPDU(self, interface, pdu):
        # encapsulage Protocol
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_out: Sending (%s) via interface %d " % (self.__ownIdentifier, pdu, interface))
        pdu=26.to_bytes(1,byteorder="little")+pdu
        if self.__sendDelay!=0:
            self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_out: Sleeping for %ds" % (self.__ownIdentifier,self.__sendDelay))
            time.sleep(self.__sendDelay)
        self.__layerPhy.API_sendData(interface, pdu)

# ----------------------------------- END NEW ------------------

# ------- DECAPSULAGE -------

    def layer2_incomingPDU(self, interface, pdu):
        # On doit décider si le paquet est pour nous ou pas.
        # On doit pour cela verifier si le protocole est le notre.
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: Received (%s) on Interface %d " % (self.__ownIdentifier, pdu, interface))
        if interface == 0 : # same ring
            # On doit décapsuler le paquet pour check le protocole.
            if pdu!=None:
                # On prend le premier octet pour check si c'est notre protocol !
                protocol=int.from_bytes(pdu[0:1],byteorder="little",signed=False)
                pdu=pdu[1:]
            if protocol == 26:
                # Numero du protocol AJA
                self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [AJA] (%s) -> Check Type\n" % (self.__ownIdentifier, pdu))
                self.layer3_incomingPDU(pdu)
            else:
                self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [Not AJA] (%s) -> layer2_out\n" % (self.__ownIdentifier, pdu))
                self.layer2_outgoingPDU(interface,pdu)
        else:
            pass

    def layer3_incomingPDU(self, pdu):
        # Type
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: Layer3_in: Received (%s)" % (self.__ownIdentifier, pdu))
        if pdu != None:
            localtype = int.from_bytes(pdu[0:1],byteorder="little",signed=False)
            pdu=pdu[1:]
        self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: Layer3_in: Type: (%s)" % (self.__ownIdentifier, pdu, str(localtype)))
        if localtype == 0:
            # Type Token
            None
        elif localtype == 1:
            # Type Accusé de reception
            None
        elif localtype == 2:
            # Type Données
            None
        elif localtype == 3:
            # Type ReqId
            None
        elif localtype == 4:
            # Type RetId
            None
        elif localtype == 5:
            # Type Update TTL
            None
        elif localtype == 6:
            # Type CountTTl
            None
        else:
            # Type invalide, destruction du paquet.

    def layer4_incomingPDU(self, type, pdu):
        # TTL
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: Layer4_in: Received (%s) type (%s)" % (self.__ownIdentifier, pdu, str(type)))
        if pdu != None:
            TTL = int.from_bytes(pdu[0:1],byteorder="little",signed=False)
            pdu = pdu[1:]
        self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: Layer4_in: TTL (%s)" % (self.__ownIdentifier, str(TTL)))
        self.layer5_outgoingPDU(type, TTL, pdu)

    def layer5_incomingPDU(self, type, TTL, pdu):
        # Destination
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: Layer5_in: Received (%s) type (%s)" % (self.__ownIdentifier, pdu, str(type)))
        if pdu != None:
            destination = int.from_bytes(pdu[0:1],byteorder="little",signed=False)
            pdu = pdu[1:]
        self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: Layer5_in: Receiving (%s) to %s " % (self.__ownIdentifier, pdu, destination))
        # Check destination is me ?





                # On prend le checksum (16bits)
                checksum = int.from_bytes(pdu[0:2],byteorder="little",signed=False)
                pdu=pdu[2:]
                print(pdu)
                
                print(HashageAJA(pdu), checksum)

                if checksum == HashageAJA(pdu):
                    # Checksum OK
                    # Intrégrité vérifié pour le moment, on regarde si il est pour nous.
                    self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [AJA] (%s) -> Checksum OK\n" % (self.__ownIdentifier, pdu))
                    self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [AJA] (%s) -> Dest ?\n" % (self.__ownIdentifier, pdu))
                    
                    # Type check
                    # On récupère le type

                    # On regarde pour qui il est !
                    dest = int.from_bytes(pdu[0:1],byteorder="little",signed=False)
                    pdu = pdu[1:]
                    self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [AJA] -> Dest %s \n" % (self.__ownIdentifier, str(dest)))
                    # Destination check
                    # -> destination

                    # Src

                    # TTL

                else:
                    # Checksum pas OK
                    # Destruction du paquet
                    print("Ca merde")

                self.layer3_incomingPDU(interface,pdu)
            else:
                self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [Not AJA] (%s) -> layer2_out\n" % (self.__ownIdentifier, pdu))
                self.layer2_outgoingPDU(interface,pdu)




    # Please adapt!
    # Take care: The parameters of incoming (data packets arriving at the computer) and outgoing (data packets leaving from the computer)
    # should generally agree with one layer difference (i.e. here we treat the applicationPort, an identifier that knows which application
    # is asked to handle the traffic
    def layer4_incomingPDU(self, source, pdu):
        time.sleep(self.__layerDelay)
        # Let us assume that this is the layer where we determine the applicationPort 
        # We also decide whether we can send immediately send a new packet or whether we need to be friendly and send a TOKEN
        # We are not friendly and send a packet if our application has one with 100% chance
        self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: Layer4_in: Received (%s) from %s " % (self.__ownIdentifier,pdu, source))
        self.application_layer_incomingPDU(False,source,pdu)

    # Please adapt
    def layer4_outgoingPDU(self, destination, applicationPort, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: Layer4_out: Sending (%s) to %s " % (self.__ownIdentifier, pdu, destination))
        self.layer3_outgoingPDU(destination, pdu)

    # Please adapt!
    # The current situation is that in this layer, the network stack takes the decision to forcibly keep the packet because it thinkgs that it is destined to this computer
    # It also authorizes immediately that a new packet can be put onto the network.
    def layer3_incomingPDU(self, interface, pdu):
        time.sleep(self.__layerDelay)
        # In this layer we know that the packet is addressed to us.
        # It may contain information that is valid or not 
        # This is another point of this obscure network protocol
        # With a chance of 50%, the packet contains valid data for us
        # With a chance of 50%, the packet does not contain valid data for us
        self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: Layer3_in: Received (%s) on interface %d " % (self.__ownIdentifier, pdu, interface))
        if random.randint(0,1):
            self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: Layer3_in: tirage (%s) -> layer4_in\n" % (self.__ownIdentifier, pdu))
            # That is, for example that the destination of the packet corresponds to us
            # We also set here the source of the packet, currently as fixed: "A"
            self.layer4_incomingPDU("A",pdu)
        else:
            self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: Layer3_in: tirage (%s) -> Packet to be destroyed\n" % (self.__ownIdentifier, pdu))
            self.layer4_incomingPDU(None,None)

    # Please adapt
    def layer3_outgoingPDU(self, destination, pdu):
        time.sleep(self.__layerDelay)
        # Here, we store the packet and wait until an empty token packet arrives
        
        self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: Layer3_out: Sending out (%s) via interface %d " % (self.__ownIdentifier, pdu, 0))
        self.layer2_outgoingPDU(0, pdu)

    # Please adapt
    def layer2_incomingPDU(self, interface, pdu):
        # On doit décider si le paquet est pour nous ou pas.
        # On doit pour cela verifier si le protocole est le notre.
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: Received (%s) on Interface %d " % (self.__ownIdentifier, pdu, interface))
        if interface == 0 : # same ring
            # Let us assume that here we treat the question whether this packet is addressed to us or not
            # The answer may be based on some obscure network protocol

            # On doit décapsuler le paquet pour check le protocole.
            if pdu!=None:
                # On prend le premier octet pour check si c'est notre protocol !
                protocol=int.from_bytes(pdu[0:1],byteorder="little",signed=False)
                pdu=pdu[1:]
            if protocol == 20:
                # Numero du protocol AJA
                self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [AJA] (%s) -> Checksum ?\n" % (self.__ownIdentifier, pdu))
                # On prend le checksum (16bits)
                checksum = int.from_bytes(pdu[0:2],byteorder="little",signed=False)
                pdu=pdu[2:]
                print(pdu)
                
                print(HashageAJA(pdu), checksum)

                if checksum == HashageAJA(pdu):
                    # Checksum OK
                    # Intrégrité vérifié pour le moment, on regarde si il est pour nous.
                    self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [AJA] (%s) -> Checksum OK\n" % (self.__ownIdentifier, pdu))
                    self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [AJA] (%s) -> Dest ?\n" % (self.__ownIdentifier, pdu))
                    
                    # Type check
                    # On récupère le type

                    # On regarde pour qui il est !
                    dest = int.from_bytes(pdu[0:1],byteorder="little",signed=False)
                    pdu = pdu[1:]
                    self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [AJA] -> Dest %s \n" % (self.__ownIdentifier, str(dest)))
                    # Destination check
                    # -> destination

                    # Src

                    # TTL

                else:
                    # Checksum pas OK
                    # Destruction du paquet
                    print("Ca merde")

                self.layer3_incomingPDU(interface,pdu)
            else:
                self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [Not AJA] (%s) -> layer2_out\n" % (self.__ownIdentifier, pdu))
                self.layer2_outgoingPDU(interface,pdu)

        
        else: # Another Ring, this is for routing, see later
            pass

    def layer2_outgoingPDU(self, interface, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_out: Sending out (%s) via interface %d " % (self.__ownIdentifier, pdu, interface))
        if self.__sendDelay!=0:
            self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_out: Sleeping for %ds" % (self.__ownIdentifier,self.__sendDelay))
            time.sleep(self.__sendDelay)
        self.__layerPhy.API_sendData(interface, pdu)

def HashageAJA(sdu):
    return int.from_bytes(sdu, byteorder='little')%65500

