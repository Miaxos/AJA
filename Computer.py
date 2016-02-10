# -*- coding: utf-8 -*-
'''
Created on 17 mai 2015

@author: barkowsky-m
'''

from NetworkStack import NetworkStack
from NetworkStackAlternative import NetworkStackAlternative
import threading
import time
from Tools.DebugOut import DebugOut

class Computer(object):

    def __init__(self, ownIdentifier, masterHost='127.0.0.1', baseport=10000, statusUpdateSeconds=1,autoEnter=True,networkStackNumber=0):

        self.__ownIdentifier=ownIdentifier

        self.__masterHost=masterHost
        self.__baseport=baseport
        self.__statusUpdateSeconds=statusUpdateSeconds
        self.__autoEnter=autoEnter
        self.__networkStackNumber=networkStackNumber
        if networkStackNumber==0:
            self.__networkstack=NetworkStack(self.__masterHost, self.__baseport, ownIdentifier, autoEnter)
        elif networkStackNumber==1:
            self.__networkstack=NetworkStackAlternative(self.__masterHost, self.__baseport, ownIdentifier, autoEnter)

        self.__appMessageList=[]
        self.__debugOut=DebugOut()
        if self.__autoEnter:
            self.startComputer()

    # The "APP" functions send a message to the other computers given in sendDestinations and counts the number of correctly received packets
    def appMessageReceived(self, source, applicationPort, message):
        self.__appThreadLock.acquire()
        self.__appMessageList.append((source,applicationPort,message))
        self.__appThreadLock.release()

    def appMessageReceive(self):
        self.__appStartedTime=time.clock()
        self.__appThreadLock=threading.Lock()

        self.__networkstack.applicationAddCallback(10,self.appMessageReceived)
        self.__loopCounter=0

        totalNumber=0
        correct=0
        wrongDestination=0
        wrongApplicationPort=0
        outOfOrder=0
        lastReceived=-1000
        while True:
            self.__loopCounter=self.__loopCounter+1
            self.__appThreadLock.acquire()
            currentList=self.__appMessageList[:]
            self.__appMessageList=[]
            self.__appThreadLock.release()

            for (source,applicationPort,message) in currentList:
                self.__debugOut.debugOutSource(self.__ownIdentifier, self.__debugOut.srcApplication,self.__debugOut.INFO,"%s: Application received message %d: %s" % (self.__ownIdentifier, totalNumber, message))

                totalNumber=totalNumber+1
                thisCorrect=True
                (messagebody, separator, remainder)=message.partition(",")
                (messagenumber, separator, remainder)=remainder.partition(",")
                (messagedestination, separator, remainder)=remainder.partition(",")

                if applicationPort!=10:
                    wrongApplicationPort=wrongApplicationPort+1
                    thisCorrect=False
                if messagedestination!=self.__ownIdentifier:
                    wrongDestination=wrongDestination+1
                    thisCorrect=False
                else:
                    try:
                        messageNumberInt=int(float(messagenumber))
                    except:
                        messageNumberInt=-2
                    if lastReceived==-1000:
                        lastReceived=messageNumberInt-1
    
                    if messageNumberInt != lastReceived+1:
                        outOfOrder=outOfOrder+1
                        thisCorrect=False


                if thisCorrect:
                    correct=correct+1
            if self.__loopCounter % self.__statusUpdateSeconds == 0:
                self.__debugOut.debugOutSource(self.__ownIdentifier, self.__debugOut.srcApplication,self.__debugOut.INFO,"%s: === Application Status of Computer %s after %.1f seconds:" % (self.__ownIdentifier, self.__ownIdentifier,(time.clock()-self.__appStartedTime)))
                self.__debugOut.debugOutSource(self.__ownIdentifier, self.__debugOut.srcApplication,self.__debugOut.INFO,"%s: === Received %d messages with %d correct (%d out of order, %d wrong destination, %d wrong application)\n" % (self.__ownIdentifier, totalNumber, correct, outOfOrder, wrongDestination, wrongApplicationPort))
            time.sleep(1)

    def appMessageSend(self, destinationIdentifier="B", numberOfMessages=5):
        self.__debugOut.debugOutSource(self.__ownIdentifier, self.__debugOut.srcComputer,self.__debugOut.INFO,"%s: Sending %d Messages from %s to %s" % (self.__ownIdentifier, numberOfMessages,self.__ownIdentifier,str(destinationIdentifier)))
        for i in range(numberOfMessages):
            for d in destinationIdentifier:
                thisMessage="Message n°%d from %s to %s,%s,%s" % (i, self.__ownIdentifier, d,i,d)
                #thisMessage="%s Sending Message n°%d to %s,%d,%s" % (self.__ownIdentifier, i,d,i,d)
                self.__networkstack.applicationSend(d,10,thisMessage)

    def debugConfigureNetworkstackDelay(self,sendDelay=None,layerDelay=None):
        self.__networkstack.configureDelay(sendDelay,layerDelay)

    # Please Adapt/Change
    def initiateToken(self):
        self.__networkstack.initiateToken()

    def startComputer(self):
        self.__application_incoming=threading.Thread(target=self.appMessageReceive)
        self.__application_incoming.start()

    def stopComputer(self):
        self.__networkstack.leaveNetwork()

    def enableGlobalDebug(self):
        self.__networkstack.enableGlobalDebug()
        
