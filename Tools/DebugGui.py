# -*- coding: utf-8 -*-

import tkinter as tk
from Tools.DebugOut import *
from scipy.sparse import data
import threading
import os
import time
        
class DebugGui(tk.Frame):

    class computerWidget():
        def __init__(self, master, debugOut, identifier, layerSelection=[1,2,11,12,13,14,15,16]):
            self.master=master
            self.identifier=identifier
            self.debugOut=debugOut
    
            self.layerFrame=[]
            self.layerLabel=[]
            self.logText=[]
            self.scrollBar=[]
            self.computerFrame=tk.Frame(self.master,borderwidth="10",relief="sunken")
            self.computerFrame.pack(side=tk.LEFT,fill=tk.BOTH,expand=1)
            self.computerLabel=tk.Label(self.computerFrame,text="Computer: "+identifier,bg="brown",fg="white")
            self.computerLabel.pack(side="top",fill="x",expand="1")
            for t in range(20):
                self.layerFrame.insert(t,tk.Frame(self.computerFrame))
                if t>self.debugOut.layerOffset :
                    self.layerLabel.insert(t,tk.Label(self.layerFrame[t],text="Layer "+str(t-self.debugOut.layerOffset)))
                else:
                    self.layerLabel.insert(t,tk.Label(self.layerFrame[t],text="DebugChannel "+str(t)))
                    
                self.scrollBar.insert(t,tk.Scrollbar(self.layerFrame[t]),)
                self.logText.insert(t, tk.Text(self.layerFrame[t],height=5,width=50,yscrollcommand=self.scrollBar[t].set))
                self.scrollBar[t]["command"]=self.logText[t].yview
                # self.logText[t].insert("0.0","Hello World\n(click me)")
                self.layerLabel[t].pack(side="top",fill="x",expand="1")
                self.scrollBar[t].pack(side="right",fill="y")
                self.logText[t].pack(side="top",fill="both",expand="1")
                # self.logText[t].insert(tk.END,self.logText[t].get(1.0,tk.END))
                    
            # We reserved widgets for all 20 debug channels and we select here which ones we display
            for t in layerSelection:
                self.layerFrame[t].pack(side=tk.TOP,fill=tk.BOTH,expand=1)
            
        def addText(self,eventTime,source,level,data):
            eventTimeStr="%.2f" % eventTime
            self.logText[source].insert(tk.END,eventTimeStr+"."+self.debugOut.levelDescription[level]+": "+data+"\n")
            self.logText[source].yview(tk.END)
            
        def changeColor(self,source,color):
            self.layerLabel[source].configure(bg=color)
            
    def __init__(self, root=None, ignoreComputer=["PhyMaster","Main"],layerSelection=[1,2,11,12,13,14,15,16],geometry=None,macosTkinterWorkaround=False):
        self.ignoreComputer=ignoreComputer
        self.layerSelection=layerSelection
        self.geometry=geometry
        
        if macosTkinterWorkaround:
            print("DebugGui-init: macosTkinterWorkaround is active, please run the launch() yourself in the main thread")
        else:
            guiThread=threading.Thread(target=self.launch,args=(root,))
            guiThread.start()
        
    def doQuit(self):
        self.root.destroy()
        os._exit(0)
        
        
    def launch(self,root=None):
        
        root = tk.Tk()
        if self.geometry!=None:
            root.geometry(self.geometry)
        self.root=root
        self.debugOut=DebugOut()
        self.displayedComputers={}
        self.messageList=[]
        self.tkThread=threading.Lock()
        
        tk.Frame.__init__(self, root)
        self.pack(fill=tk.BOTH,expand=1)
#        self.displayedComputers["A"]=self.computerWidget(self,self.debugOut,"A")
#        self.displayedComputers["B"]=self.computerWidget(self,self.debugOut,"B")
#        self.displayedComputers["PhyMaster"]=self.computerWidget(self,self.debugOut,"PhyMaster")
        self.configFrame=tk.Frame(self)
        self.configFrame.pack(side="left",fill=tk.BOTH,expand=0)
        self.QUIT = tk.Button(self.configFrame, text="QUIT", fg="red", command=self.doQuit)
        self.QUIT.pack(side="bottom",fill=tk.Y,expand=1)
        
        
        self.debugOut.addGlobalListenCallback(self.handleDebugOut)
        
        # This is required as tk is not thread-safe
        self.root.after(100,self.updateTKInterface)
        self.mainloop()

    def updateTKInterface(self):
        self.tkThread.acquire()
        if len(self.messageList)>0:
            for identifier in self.displayedComputers.keys():
                for source in range(20):
                    self.displayedComputers[identifier].changeColor(source,"gray")
        while len(self.messageList)>0:
            eventTime,identifier,source,level,data=self.messageList.pop(0)
            if identifier not in self.ignoreComputer:
                if identifier not in self.displayedComputers.keys():
                    self.displayedComputers[identifier]=self.computerWidget(self,self.debugOut,identifier,self.layerSelection)
                self.displayedComputers[identifier].changeColor(source,"red")
                self.displayedComputers[identifier].addText(eventTime,source,level,data)
        self.tkThread.release()
        self.root.after(100,self.updateTKInterface)



    def handleDebugOut(self,eventTime,identifier,source,level,data):
        self.tkThread.acquire()
        self.messageList.append((eventTime,identifier,source,level,data))
        self.tkThread.release()
        
