# -*- coding: utf-8 -*-
import socket
import threading

class TCPServer(object):
    '''
    This class opens a TCP port connection as server
    '''

    def serverConnectionThread(self, connection, clientAddr):
        if self.callBackConnect is not None:
            self.callBackConnect(self, connection, clientAddr)
        while True:
            try:
                data=False
                headerLen=9
                header=b''
                while headerLen-len(header)>0:
                    header = header+connection.recv(9)
                    if len(header)==0:
                        break
                if len(header) == 0:
                    print("TCPServer - Got a short read of 0 bytes on header for connection ", connection, "assuming disconnect")
                    if self.callBackHandleSocketError is not None:
                        self.callBackHandleSocketError(self, connection, clientAddr)
                else:
                    try:
                        dataLen=int(header[0:8].decode("iso8859-1"))
                    except:
                        print("TCPServer : Out of synchronisation, cannot read headerlength")
                        dataLen=0
                    
                    data=b''
                    while(dataLen-len(data)>0):
                        data=data+connection.recv(dataLen-len(data))
            except socket.error as msg:
                # In case that the socket recv function returned an error, we need to check whether the socket was closed
                print("Error serverConnectionThread on connection.recv received ", msg)
                if self.callBackHandleSocketError is not None:
                    self.callBackHandleSocketError(self, connection, clientAddr)
                break

            if not data:
                break
            # print("Server received ",data," on ",clientAddr)
            if self.callBackReceive is not None:
                self.callBackReceive(self, connection, clientAddr, data.decode("utf-8"))
            if self.callBackReceiveBytes is not None:
                self.callBackReceiveBytes(self, connection, clientAddr, data)



    def serverListenThread(self):
        self.serverSocket=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.serverSocket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            self.serverSocket.bind((self.host,self.port))
            self.serverSocket.listen(10)
        except socket.error as msg:
            print("Server bind has failed %s" % msg)
            self.serverSocket.close()
            self.serverStarted.release()
            return
        self.serving=True
        self.stopServing=False
        self.serverStarted.release()
        while (not self.stopServing):
            connection, clientAddr = self.serverSocket.accept()
            # print("  Server connected <-", clientAddr)
            connectionThread=threading.Thread(target=self.serverConnectionThread,args=[connection, clientAddr])
            connectionThread.start()
        self.serverSocket.shutdown(socket.SHUT_RDWR)
        self.serving=False
        self.serverSocket.close()

    def send(self, data):
        self.sendBytes(data.encode("urf-8"))

    def sendBytes(self, data):
        try:
            header=("%8d," % len(data)).encode("iso8859-1")
            self.serverSocket.sendall(header+data)
        except socket.error as msg:
            print("  TCPServer : Send failed %s" % msg)
            if self.callBackHandleSocketError is not None:
                self.callBackHandleSocketError(self, self.serverSocket, (self.host, self.port))

    def sendConnection(self, connection, data):
        self.sendConnectionBytes(connection,data.encode("utf-8"))

    def sendConnectionBytes(self, connection, data):
        try:
            header=("%8d," % len(data)).encode("iso8859-1")
            connection.sendall(header+data)
        except socket.error as msg:
            print("  TCPServer : Send failed %s" % msg)
            if self.callBackHandleSocketError is not None:
                self.callBackHandleSocketError(self, connection, (self.host, self.port))


    def startServer(self):
        self.serverStarted=threading.Lock()
        self.serverStarted.acquire()

        self.listenThread=threading.Thread(target=self.serverListenThread)
        self.listenThread.start()
        self.serverStarted.acquire()

    def stopServer(self):
        self.stopServing=True

    def isServing(self):
        return self.serving


    def __init__(self, host, port, callBackReceive=None, callBackReceiveBytes=None, callBackConnect=None, callBackHandleSocketError=None):
        self.host=host
        self.port=port
        self.callBackReceive=callBackReceive
        self.callBackReceiveBytes=callBackReceiveBytes
        self.callBackConnect=callBackConnect
        self.callBackHandleSocketError=callBackHandleSocketError

        self.serving=False
        self.serverStarted=False
        self.startServer()
