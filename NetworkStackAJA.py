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
        # On définit le maître par un envoie d'un token
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"Initiating TOKEN" )
        tokenThread=threading.Thread(target=self.application_layer_outgoingPDU, args=(0,))
        tokenThread.start()

    # Please adapt if required : This is the top layer that usually sends the data to the application
    # If pdu is None, the packet is not valid
    # forceToken determines that the return packet needs to be a TOKEN
    def application_layer_incomingPDU(self, localtype, source, pdu):
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
        if (localtype == 2):
            self.application_layer_outgoingPDU(3)

    # Please adapt if required: This is the top layer that retrieves one element from the application layer 
    def application_layer_outgoingPDU(self, localtype=0):
        # Layer 5 dans l'application (Le premier element du paquet se trouve dedans)
        # On récupère les infos de l'application, dont le type de paquet qu'on balance, pour qui, avec les données.
        time.sleep(self.__layerDelay)
        self.outgoingPacketStackLock.acquire()
        if localtype==0:
            destination= 1
            applicationPort=20
            sdu="TOKEN"
            type = 0
        else:
            if (localtype == 1): 
                # Après l'accusé de réception
                if(len(self.outgoingPacketStack)==0):
                    # On balance le token
                    destination= 1
                    applicationPort=20
                    sdu="TOKEN"
                    type = 0
                else:
                    destination,applicationPort, sdu=self.outgoingPacketStack.pop()
                    type = 2
            elif (localtype == 2):
                # Type message
                # Il s'agit d'envoyer un message comme quoi elle a bien reçu les données.
                None
            elif (localtype == 3):
                # Il s'agit de recevoir l'accusé de réception.
                # On balance donc le token des qu'on a reçu l'accusé de reception
                destination= 1
                applicationPort=20
                sdu="TOKEN"
                type = 0

        self.outgoingPacketStackLock.release()

        # Data
        pdu=sdu.encode("UTF-8")
        
        #Dest
        pdu=applicationPort.to_bytes(1,byteorder="little",signed=False)+pdu

        self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: application_layer_out: sending (%s) " % (self.__ownIdentifier,pdu))
        self.layer7_outgoingPDU(DestinationtoID(destination), ord(self.__ownIdentifier), type, pdu, 255)

# --------- ENCAPSULAGE --------


    def layer7_outgoingPDU(self, destination, source, type, pdu, TTL=255):
        # encapsulage du checksum
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,7,self.__debugOut.INFO,"%s: Layer7_out: Sending (%s) to %s " % (self.__ownIdentifier, pdu, destination))
        
        pdu=HashageAJA(pdu).to_bytes(2,byteorder="little")+pdu
        
        self.layer6_outgoingPDU(destination, source, type, pdu, TTL)

    def layer6_outgoingPDU(self, destination, source, type, pdu, TTL=255):
        # encapsulage source
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,6,self.__debugOut.INFO,"%s: Layer6_out: Sending (%s) to %s " % (self.__ownIdentifier, pdu, destination))
        pdu=source.to_bytes(1,byteorder="little")+pdu
        self.layer5_outgoingPDU(destination, type, pdu, TTL)

    def layer5_outgoingPDU(self, destination, type, pdu, TTL=255):
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
        self.layer2_outgoingPDU(0, pdu)

    #4 -> TTL

    def layer2_outgoingPDU(self, interface, pdu):
        # encapsulage Protocol
        time.sleep(self.__layerDelay)
        proto = 26
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_out: Sending (%s) via interface %d " % (self.__ownIdentifier, pdu, interface))
        pdu=proto.to_bytes(1,byteorder="little")+pdu
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
        self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: Layer3_in: Type: (%s)" % (self.__ownIdentifier, str(localtype)))
        if localtype == 0:
            # Token
            self.layer4_incomingPDU(localtype, pdu)
        elif localtype == 1:
            # Type Accusé de reception
            # Il s'agit de voir si on a fait le tour.
            self.layer4_incomingPDU(localtype,pdu)
        elif localtype == 2:
            # Type Données
            # Message
            self.layer4_incomingPDU(localtype, pdu)
        elif localtype == 3:
            # accusé message reçu
             self.layer4_incomingPDU(localtype, pdu)
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
            pass
    def layer4_incomingPDU(self, localtype, pdu):
        # TTL
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: Layer4_in: Received (%s) type (%s)" % (self.__ownIdentifier, pdu, str(localtype)))
        if pdu != None:
            TTL = int.from_bytes(pdu[0:1],byteorder="little",signed=False)
            pdu = pdu[1:]
        self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: Layer4_in: TTL (%s)" % (self.__ownIdentifier, str(TTL)))
        if localtype == 0:
            self.layer5_incomingPDU(localtype, TTL, pdu)
        elif localtype == 1:
            # Type Accusé de reception
            # On decrease le TTL
            TTL = TTL - 1
            self.layer5_incomingPDU(localtype,TTL,pdu)
        elif localtype == 2:
            # Type Données
            # On decrease le TTL
            TTL = TTL - 1
            self.layer5_incomingPDU(localtype,TTL,pdu)
        elif localtype == 3:
            TTL = TTL - 1
            self.layer5_incomingPDU(localtype,TTL,pdu)
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
            pass
        # self.layer5_outgoingPDU(localtype, pdu, TTL)

    def layer5_incomingPDU(self, localtype, TTL, pdu):
        # destination
        time.sleep(self.__layerDelay)
        if pdu != None:
            destination = int.from_bytes(pdu[0:1],byteorder="little",signed=False)
            pdu = pdu[1:]
        self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: Layer5_in: Destination (%s)" % (self.__ownIdentifier, str(destination)))
        if localtype == 0:
            self.layer6_incomingPDU(destination, localtype, TTL, pdu)
        elif localtype == 1:
            # Type Accusé de reception
            if destination != ord(self.__ownIdentifier):
                # Si c'est pas nous alors
                # On fait tourner.
                self.layer5_outgoingPDU(destination, localtype, pdu, TTL)
            else:
                # On a terminé le tour donc on diffuse un message.
                self.layer6_incomingPDU(destination, localtype, TTL, pdu)
        elif localtype == 2:
            # Type Données
            # Message
            if destination != ord(self.__ownIdentifier):
                # Si c'est pas nous alors
                # On fait tourner.
                self.layer5_outgoingPDU(destination, localtype, pdu, TTL)
            else:
                # On a terminé le tour donc on diffuse un message.
                self.layer6_incomingPDU(destination, localtype, TTL, pdu)
        elif localtype == 3:
            # Accusé de réception message
            if destination != ord(self.__ownIdentifier):
                self.layer5_outgoingPDU(destination, localtype, pdu, TTL)
            else:
                self.application_layer_outgoingPDU(0)
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
            pass

    def layer6_incomingPDU(self, destination, localtype, TTL, pdu):
        # source
        time.sleep(self.__layerDelay)
        if pdu != None:
            source = int.from_bytes(pdu[0:1],byteorder="little",signed=False)
            pdu = pdu[1:]
        self.__debugOut.debugOutLayer(self.__ownIdentifier,6,self.__debugOut.INFO,"%s: Layer6_in: Source (%s)" % (self.__ownIdentifier, str(destination)))
        if localtype == 0:
            # On balance un accusé de reception
            self.layer6_outgoingPDU(DestinationtoID(self.__ownIdentifier), ord(self.__ownIdentifier), 1, pdu, 255)
        elif localtype == 1:
            # Type Accusé de reception
            self.application_layer_outgoingPDU(localtype)
        elif localtype == 2:
            # Type Données
            # Rien de particulier avec la source
            self.layer7_incomingPDU(localtype, source, pdu)
        elif localtype == 3:
            # Reception message accusé
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
            pass

    def layer7_incomingPDU(self, localtype, source, pdu):
        time.sleep(self.__layerDelay)
        if pdu != None:
            checksum = int.from_bytes(pdu[0:2],byteorder="little",signed=False)
            pdu = pdu[2:]
        if (HashageAJA(pdu) == checksum):
            self.application_layer_incomingPDU(localtype, source, pdu)
        else:
            # Destruction du paquet
            None

def HashageAJA(sdu):
    return int.from_bytes(sdu, byteorder='little')%65500

def DestinationtoID(dest):
    if (type(dest) == str):
        return ord(dest[0])
    else:
        return dest

