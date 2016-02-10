# -*- coding: utf-8 -*-
# from PhyCoordinator.PhyNetwork import PhyNetwork

import threading
import sys
import time

class _Singleton(type):
    _instances = {}
    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(_Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]

class Singleton(_Singleton('SingletonMeta', (object,), {})): pass

class DebugOut(Singleton):
    '''
    classdocs
    '''

    def __init__(self, phyNetwork=None):
        self.phyNetwork=phyNetwork
        self.outputLock=threading.Lock()
        
        self.NONE=0
        self.ERROR=1
        self.WARNING=2
        self.INFO=3
        self.ALL=4
        self.levelDescription=["NONE","ERROR","WARNING","INFO","ALL"]
        
        self.srcComputer=1
        self.srcApplication=2
        
        self.debugLevel=[self.NONE] * 20;
        self.layerOffset=10
        self.localListenerCallback=[]
        self.globalListenerCallback=[]
        self.localHistory=[]
        self.globalHistory=[]
        self.startTime=time.time()
        
    def globaldebugOutSource(self,eventTime,identifier,source,level,data):
        self.globalHistory.append((eventTime,identifier,source,level,data))
        for callbackFunction in self.globalListenerCallback:
            callbackFunction(eventTime,identifier,source,level,data)
    
    def addGlobalListenCallback(self,callbackFunction):
        for (eventTime,identifier,source,level,data) in self.globalHistory:
            callbackFunction(eventTime,identifier,source,level,data)
        self.globalListenerCallback.append(callbackFunction)

    def addLocalListenCallback(self,callbackFunction):
        self.outputLock.acquire()
        self.localListenerCallback.append(callbackFunction)
        for (eventTime,identifier,source,level,data) in self.localHistory:
            callbackFunction(eventTime,identifier,source,level,data)
        self.outputLock.release()
        
    def setDebugLevelForSource(self, source, value):
        self.debugLevel[source]=value
    
    # Allows to set the debug level for each network layer
    def setDebugLevelForLayer(self, layer, value):
        self.setDebugLevelForSource(self.layerOffset+layer, value)
        
    def debugOutSource(self,identifier,source,level,data):
        eventTime=time.time()-self.startTime
        # print("Adding to localHistory ",len(data),data)
        self.localHistory.append((eventTime,identifier,source,level,data))
        for callbackFunction in self.localListenerCallback:
            callbackFunction(eventTime,identifier,source,level,data)
        if level <= self.debugLevel[source]  :
            self.outputLock.acquire()
            if source >= self.layerOffset :
                print("ID:%s LAYER%d - %s - %s" % (identifier,source-self.layerOffset,self.levelDescription[level],data))
                sys.stdout.flush()
            else:
                print("ID:%s SRC%d - %s - %s" % (identifier,source,self.levelDescription[level],data))
                sys.stdout.flush()
            self.outputLock.release()
            
        
    # Prints out on the debug interface, specifying the network layer and level    
    def debugOutLayer(self,identifier,layer,level,data):
        self.debugOutSource(identifier,self.layerOffset+layer, level, data)
        
        