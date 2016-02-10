# -*- coding: utf-8 -*-
import socket
import threading

class TCPClient(object):
    '''
    Client for TCP Connections
    '''

    '''
    Threaded function listening for incoming connections. Gets an interruption when the socket is closed by means of the socket handling OS functions.
    '''
    def clientListenThread(self, connection, clientAddr):
        # Signal that the listen thread has started
        self.listenStarted.release()
        while True:
            try:
                # Read data from the socket
                data=False
                headerLen=9
                header=b''
                while headerLen-len(header)>0:
                    header = header+connection.recv(9)
                    if len(header)==0:
                        break
                if len(header) == 0:
                    print("TCPClient - Got a short read of 0 bytes on header for connection ", connection, "assuming disconnect")
                    if self.callBackHandleSocketError is not None:
                        self.callBackHandleSocketError(self, connection, clientAddr)
                else:
                    try:
                        dataLen=int(header[0:8].decode("iso8859-1"))
                    except:
                        print("TCPClient : Out of synchronisation, cannot read headerlength")
                        dataLen=0

                    data=b''
                    while(dataLen-len(data)>0):
                        data=data+connection.recv(dataLen-len(data))
            except socket.error as msg:
                # In case that the socket recv function returned an error, we need to check whether the socket was closed
                self.connectedLock.acquire()
                if self.connected:
                    self.connectedLock.release()
                    print("Error clientListenThread on connection.recv received ", msg)
                    if self.callBackHandleSocketError is not None:
                        self.callBackHandleSocketError(self, connection, clientAddr)
                else:
                    self.connectedLock.release()
                # If it was, we end the thread
                break
            
            # print("Client received ",data," on ",clientAddr)
            # If everything worked out fine, we call the callback function
            if self.callBackReceive is not None:
                self.callBackReceive(self, connection, clientAddr, data.decode("utf-8"))
            if self.callBackReceiveBytes is not None:
                self.callBackReceiveBytes(self, connection, clientAddr, data)
                
            

    def startClient(self):
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clientSocket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            self.clientSocket.connect((self.host, self.port))
        except socket.error as msg:
            print("  TCPClient : Connection failed %s" % msg)
            return False
        # print("  Client connected ->", (self.host, self.port, self.clientSocket))
        

        self.connectedLock.acquire()
        self.connected=True
        self.connectedLock.release()
        
        self.listenStarted.acquire()
        
        self.listenThread=threading.Thread(target=self.clientListenThread, args=(self.clientSocket,(self.host, self.port)))
        self.listenThread.start()
        self.listenStarted.acquire()
        return True
      
    def stopClient(self):
        # print("============> Socket shutdown : ", self.clientSocket, self.clientSocket, self.host, self.port)
        self.connectedLock.acquire()
        self.clientSocket.shutdown(socket.SHUT_RDWR)
        self.clientSocket.close()
        self.connected=False
        self.connectedLock.release()

    def send(self, data):
        self.sendBytes(data.encode("utf-8"))

    def sendBytes(self, data):
        self.connectedLock.acquire()
        if self.connected:
            try:
                header=("%8d," % len(data)).encode("iso8859-1")
                self.clientSocket.sendall(header+data)
            except socket.error as msg:
                print("  TCPClient : Send failed %s" % msg)
                if self.callBackHandleSocketError is not None:
                    self.callBackHandleSocketError(self, self.clientSocket, (self.host, self.port))

        self.connectedLock.release()

    def isConnected(self):
        return self.connected

    def __init__(self, host, port, callBackReceive=None, callBackReceiveBytes=None, callBackHandleSocketError=None):
        self.host=host
        self.port=port
        self.callBackReceive=callBackReceive
        self.callBackReceiveBytes=callBackReceiveBytes
        self.callBackHandleSocketError=callBackHandleSocketError
        self.listenStarted=threading.Lock()        
        self.connectedLock=threading.Lock()
        self.connected=False
        
        self.startClient()

        