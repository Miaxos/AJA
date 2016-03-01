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
        self.__layerPhy=LayerPhy.LayerPhy(ownIdentifier, upperLayerCallbackFunction=self.layerT1_incomingPDU, masterHost=masterHost, baseport=baseport, autoEnter=autoEnter)
        # You may want to change the following part
        self.AppSend=0
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
#
# On limite les messages à 255 caractères.
# Un train peut manage 3 messages differents.
#
#
#############################################################################################################################################

    # Please change: This sends the first TOKEN to the ring
    # In fact, sending a TOKEN requires the creation of a new thread
    def initiateToken(self):
        # On définit le maître par un envoie d'un token
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"Initiating TOKEN" )
        tokenThread=threading.Thread(target=self.layerT5_outgoingPDU, args=(3, self.__ownIdentifier, self.application_layer_outgoingPDU(10)[0], self.application_layer_outgoingPDU(10)[0], self.application_layer_outgoingPDU(10)[0]))
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
            next, message = self.application_layer_outgoingPDU(5)
            return next, message

    # Please adapt if required: This is the top layer that retrieves one element from the application layer 
    def application_layer_outgoingPDU(self, localtype=0):
        # Layer 5 dans l'application (Le premier element du paquet se trouve dedans)
        # On récupère les infos de l'application, dont le type de paquet qu'on balance, pour qui, avec les données.
        time.sleep(self.__layerDelay)
        self.outgoingPacketStackLock.acquire()
        if localtype==0:
            # self.layerT5_outgoingPDU(0, self.__ownIdentifier, self.application_layer_outgoingPDU(10), self.application_layer_outgoingPDU(10), application_layer_outgoingPDU(10))
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
                sdu="Reception"
                type = 0
            elif (localtype == 5):
                if(len(self.outgoingPacketStack)==0):
                    # On balance le token
                    destination= 1
                    applicationPort=20
                    sdu="VIDE"
                    type = 10
                else:
                    destination,applicationPort, sdu=self.outgoingPacketStack.pop()
                    type = 2
            elif (localtype == 10):
                sdu = "VIDE"
                type = 10
                applicationPort = 20
                destination = 1
        while CheckMsg(sdu.encode("UTF-8")):
            sdu = ' ' + sdu
        self.outgoingPacketStackLock.release()

        # Data
        pdu=sdu.encode("UTF-8")
        
        #Dest
        pdu=applicationPort.to_bytes(1,byteorder="little",signed=False)+pdu

        self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: application_layer_out: sending (%s) " % (self.__ownIdentifier,pdu))
        next, message = self.layer7_outgoingPDU(DestinationtoID(destination), ord(self.__ownIdentifier), type, pdu, 255)
        return next, message

# --------- ENCAPSULAGE --------


    def layer7_outgoingPDU(self, destination, source, type, pdu, TTL=255):
        # encapsulage du checksum
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,7,self.__debugOut.INFO,"%s: Layer7_out: Sending (%s) to %s " % (self.__ownIdentifier, pdu, destination))
        
        pdu=HashageAJA(pdu).to_bytes(2,byteorder="little")+pdu

        next, message = self.layer6_outgoingPDU(destination, source, type, pdu, TTL)
        return next, message

    def layer6_outgoingPDU(self, destination, source, type, pdu, TTL=255):
        # encapsulage source
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,6,self.__debugOut.INFO,"%s: Layer6_out: Sending (%s) to %s " % (self.__ownIdentifier, pdu, destination))
        pdu=source.to_bytes(1,byteorder="little")+pdu
        next, message = self.layer5_outgoingPDU(destination, type, pdu, TTL)
        return next, message

    def layer5_outgoingPDU(self, destination, type, pdu, TTL=255):
        # encapsulage destination
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: Layer5_out: Sending (%s) to %s " % (self.__ownIdentifier, pdu, destination))
        pdu=destination.to_bytes(1,byteorder="little")+pdu
        next, message = self.layer4_outgoingPDU(type, pdu, TTL)
        return next, message

    def layer4_outgoingPDU(self, type, pdu, TTL=255):
        # encapsulage TTL
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: Layer4_out: Sending (%s)" % (self.__ownIdentifier, pdu))
        pdu=TTL.to_bytes(1,byteorder="little")+pdu
        next, message = self.layer3_outgoingPDU(type, pdu)
        return next, message

    def layer3_outgoingPDU(self, type, pdu):
        # encapsulage Type
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: Layer3_out: Sending (%s)" % (self.__ownIdentifier, pdu))
        pdu=type.to_bytes(1,byteorder="little")+pdu
        if type == 10:
            message = 0
        else:
            message = 1
        next = self.layer2_outgoingPDU(0, pdu)
        return next, message

    #4 -> TTL

    def layer2_outgoingPDU(self, interface, pdu):
        # encapsulage Protocol
        time.sleep(self.__layerDelay)
        proto = 26
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_out: Sending (%s) via interface %d " % (self.__ownIdentifier, pdu, interface))
        pdu=proto.to_bytes(1,byteorder="little")+pdu
        # if self.__sendDelay!=0:
        #     self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_out: Sleeping for %ds" % (self.__ownIdentifier,self.__sendDelay))
        #     time.sleep(self.__sendDelay)
        # self.__layerPhy.API_sendData(interface, pdu)
        return pdu

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
                next, message = self.layer3_incomingPDU(pdu)
                return next, message
            else:
                self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: Layer2_in: [Not AJA] (%s) -> layer2_out\n" % (self.__ownIdentifier, pdu))
                next = self.layer2_outgoingPDU(interface,pdu)
                return next, 1
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
            next, message = self.layer4_incomingPDU(localtype, pdu)
            return next, message
        elif localtype == 1:
            # Type Accusé de reception
            # Il s'agit de voir si on a fait le tour.
            next, message = self.layer4_incomingPDU(localtype,pdu)
            return next, message
        elif localtype == 2:
            # Type Données
            # Message
            next, message = self.layer4_incomingPDU(localtype, pdu)
            return next, message
        elif localtype == 3:
            # accusé message reçu
             next, message = self.layer4_incomingPDU(localtype, pdu)
             return next, message
        elif localtype == 4:
            # Type RetId
            None
        elif localtype == 5:
            # Type Update TTL
            None
        elif localtype == 6:
            # Type CountTTl
            None
        elif localtype == 10:
            next, message = self.application_layer_outgoingPDU(5)
            return next, message
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
            next, message = self.layer5_incomingPDU(localtype, TTL, pdu)
            return next, message
        elif localtype == 1:
            # Type Accusé de reception
            # On decrease le TTL
            TTL = TTL - 1
            next, message = self.layer5_incomingPDU(localtype,TTL,pdu)
            return next, message
        elif localtype == 2:
            # Type Données
            # On decrease le TTL
            TTL = TTL - 1
            next, message = self.layer5_incomingPDU(localtype,TTL,pdu)
            return next, message
        elif localtype == 3:
            TTL = TTL - 1
            next, message = self.layer5_incomingPDU(localtype,TTL,pdu)
            return next, message
        elif localtype == 4:
            # Type RetId
            None
        elif localtype == 5:
            # Type Update TTL
            None
        elif localtype == 10:
            next, message = self.layer5_incomingPDU(localtype,TTL,pdu)
            return next, message
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

            next, message = self.layer6_incomingPDU(destination, localtype, TTL, pdu)
            return next, message
        elif localtype == 1:
            # Type Accusé de reception
            if destination != ord(self.__ownIdentifier):
                # Si c'est pas nous alors
                # On fait tourner.
                next, message = self.layer5_outgoingPDU(destination, localtype, pdu, TTL)
                return next, message
            else:
                # On a terminé le tour donc on diffuse un message.
                next, message = self.layer6_incomingPDU(destination, localtype, TTL, pdu)
                return next, message
        elif localtype == 2:
            # Type Données
            # Message
            if destination != ord(self.__ownIdentifier):
                # Si c'est pas nous alors
                # On fait tourner.
                next, message = self.layer5_outgoingPDU(destination, localtype, pdu, TTL)
                return next, message
            else:
                # On a terminé le tour donc on diffuse un message.
                next, message = self.layer6_incomingPDU(destination, localtype, TTL, pdu)
                return next, message
        elif localtype == 3:
            # Accusé de réception message
            if destination != ord(self.__ownIdentifier):
                next, message = self.layer5_outgoingPDU(destination, localtype, pdu, TTL)
                return next, message
            else:
                next, message = self.application_layer_outgoingPDU(0)
                return next, message
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
            next, message = self.layer6_outgoingPDU(DestinationtoID(self.__ownIdentifier), ord(self.__ownIdentifier), 1, pdu, 255)
            return next, message
        elif localtype == 1:
            # Type Accusé de reception
            next, message = self.application_layer_outgoingPDU(localtype)
            return next, message
        elif localtype == 2:
            # Type Données
            # Rien de particulier avec la source
            next, message = self.layer7_incomingPDU(localtype, source, pdu)
            return next, message
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
            next, message = self.application_layer_incomingPDU(localtype, source, pdu)
            return next, message
        else:
            # Destruction du paquet
            print("FUCK OFF")
            None

############
############ MULTIPLEXAGE 
############

# Gestion du train [NbMessage | @SRC | Slot1 | Slot2 | Slot3 ]

    def layerT1_incomingPDU(self, interface, pdu):
        time.sleep(self.__layerDelay)

        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: LayerTT2_in: Received (%s) on Interface %d longueur pdu (%s) " % (self.__ownIdentifier, pdu, interface, len(pdu)))
        if interface == 0 : # same ring
            # On doit décapsuler le paquet pour check le protocole.
            if pdu!=None:
                # On prend le premier octet pour check si c'est notre protocol !
                nbmessage=int.from_bytes(pdu[0:1],byteorder="little",signed=False)
                pdu=pdu[1:]
                self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: LayerTT2_in: [AJA-TRAIN] (%s) -> @SRC ?\n" % (self.__ownIdentifier, pdu))
                self.layerT2_incomingPDU(nbmessage, pdu)
        else:
            pass

    def layerT2_incomingPDU(self, nbmessage, pdu):
        time.sleep(self.__layerDelay)
        if pdu!=None:
            source = int.from_bytes(pdu[0:1],byteorder="little",signed=False)
            pdu=pdu[1:]
            self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: LayerTT3_in: Received (%s) @src (%s) ? " % (self.__ownIdentifier, pdu, source))
        if (nbmessage == 0) and (source == ord(self.__ownIdentifier)):
            # On est revenu au début, donc on donne le token avant de recommencer.
            self.layerT3_incomingPDU(nbmessage, source, pdu, True)
        else:
            # Sinon on s'en balance et on continue
            if (nbmessage == 0):
                # On a pas de messages alors on
                # self.layerTX_outgoingPDU()
                self.layerT3_incomingPDU(nbmessage, source, pdu)
            else:
                # On a des messages
                self.layerT3_incomingPDU(nbmessage, source, pdu)

    def layerT3_incomingPDU(self, nbmessage, source, pdu, token = False):
        time.sleep(self.__layerDelay)
        if pdu!=None:
            # print("TRYYY")
            # print(pdu)
            slot1 = pdu[0:49]
            pdu = pdu[49:]
            self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: LayerTT4_in: slot1 (%s) ? " % (self.__ownIdentifier, slot1))
            if token:
                newslot1, message = self.application_layer_outgoingPDU(0)
            else:
                newslot1, message = self.layer2_incomingPDU(0, slot1)
            newnbmessage = message
            self.layerT4_incomingPDU(newnbmessage, source, newslot1, pdu)

    def layerT4_incomingPDU(self, newnbmessage, source, newslot1, pdu):
        time.sleep(self.__layerDelay)
        if pdu!=None:
            slot2 = pdu[0:49]
            pdu = pdu[49:]
            self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: LayerTT5_in:slot2 (%s) ? " % (self.__ownIdentifier, slot2))
            newslot2, message = self.layer2_incomingPDU(0, slot2)
            nbmessage = message + newnbmessage
            self.layerT5_incomingPDU(nbmessage, source, newslot1, newslot2, pdu)

    def layerT5_incomingPDU(self, nbmessage, source, newslot1, newslot2, pdu):
        time.sleep(self.__layerDelay)
        if pdu!=None:
            slot3 = pdu[0:]
            self.__debugOut.debugOutLayer(self.__ownIdentifier,6,self.__debugOut.INFO,"%s: LayerTT6_in:slot3 (%s) ? " % (self.__ownIdentifier, slot3))
            newslot3, message = self.layer2_incomingPDU(0, slot3)
            newnbmessage = message + nbmessage
            self.layerT5_outgoingPDU(newnbmessage, source, newslot1, newslot2, newslot3)

    def layerT5_outgoingPDU(self, newnbmessage, source, newslot1, newslot2, newslot3):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,6,self.__debugOut.INFO,"%s: LayerTT6_out: Received (%s)  ? " % (self.__ownIdentifier, newslot3))
        pdu = newslot3
        self.layerT4_outgoingPDU(newnbmessage, source, newslot1, newslot2, pdu)

    def layerT4_outgoingPDU(self, newnbmessage, source, newslot1, newslot2, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,5,self.__debugOut.INFO,"%s: LayerTT5_out: Received (%s) slot2 (%s) ? " % (self.__ownIdentifier, pdu, newslot2))
        pdu = newslot2+pdu
        self.layerT3_outgoingPDU(newnbmessage, source, newslot1, pdu)

    def layerT3_outgoingPDU(self, newnbmessage, source, newslot1, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,4,self.__debugOut.INFO,"%s: LayerTT4_out: Received (%s) slot2 (%s) ? " % (self.__ownIdentifier, pdu, newslot1))
        pdu = newslot1+pdu
        self.layerT2_outgoingPDU(newnbmessage, source, pdu)

    def layerT2_outgoingPDU(self, newnbmessage, source, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,3,self.__debugOut.INFO,"%s: LayerTT3_out: Received (%s) LA ? " % (self.__ownIdentifier, pdu))
        src = DestinationtoID(source)
        print(pdu)
        print(src)
        pdu = src.to_bytes(1,byteorder="little")+pdu
        self.layerT1_outgoingPDU(0, newnbmessage, pdu)

    def layerT1_outgoingPDU(self, interface, newnbmessage, pdu):
        time.sleep(self.__layerDelay)
        self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: LayerTT2_out: Received (%s) BY ? " % (self.__ownIdentifier, pdu))
        pdu = newnbmessage.to_bytes(1,byteorder="little")+pdu
        if self.__sendDelay!=0:
            self.__debugOut.debugOutLayer(self.__ownIdentifier,2,self.__debugOut.INFO,"%s: LayerTT2_out: Sleeping for %ds" % (self.__ownIdentifier,self.__sendDelay))
            time.sleep(self.__sendDelay)
        self.__layerPhy.API_sendData(interface, pdu)




def CheckMsg(string):
    return len(string) <= 40

def HashageAJA(sdu):
    return int.from_bytes(sdu, byteorder='little')%65500

def DestinationtoID(dest):
    if (type(dest) == str):
        return ord(dest[0])
    else:
        return dest

