#A SecCLIChat server
from basechat import SecCLIChatBase
from socket import socket, AF_INET, SOCK_STREAM, error as SocketError

class SecCLIChatServer(SecCLIChatBase):
    
    def __init__(self, bindAddress = '127.0.0.1', bindPort = 7070):
        from re import compile
        from threading import Thread

        self.address = self.validateAddress(bindAddress)
        self.port = self.validatePort(bindPort)

        #A dictionary mapping client session IDs (keys) to client recv sockets (values)
        self.msgRecvSocketMap = {}

        #A dictionary mapping client session IDs to client usernames
        self.usernameMap = {}

        #A dictionary mapping client session IDs to shared keys
        self.keyMap = {}

        self.signonRegex = compile(r'(.+);([\dA-Fa-f]{8}-[\dA-Fa-f]{4}-[\dA-Fa-f]{4}-[\dA-Fa-f]{4}-[\dA-Fa-f]{12})')
        

        self.serverThread = Thread(target = self.run, name = "serverThread", daemon = True)

    
    def handleConnection(self, clientSocket, clientAddress):
        from re import match
        from diffiehellman import generateKey, getPublicKey, getSharedKey

        clientMessage = self.readFromSocket(clientSocket)
        signonMatch = self.signonRegex.match(clientMessage)

        if clientMessage.lower() == "kill":
            clientSocket.close()
        
        #If the message is a signon, add them to the map
        elif signonMatch != None:
            username, sessionID = signonMatch.group(1, 2)
            self.msgRecvSocketMap[sessionID] = clientSocket
            self.usernameMap[sessionID] = username

            self.sendToSocket(clientSocket, "RECV Socket registered")

            privateKey = generateKey()

            self.keyMap[sessionID] = getSharedKey(privateKey, int(self.readFromSocket(clientSocket)))

            publicKey = getPublicKey(privateKey)
            self.sendToSocket(clientSocket, str(publicKey))

            #Wait for socket ok
            self.readFromSocket(clientSocket)

            #Relay a connection message
            self.relayMessage("/c", username)


        #If the client is not a signon or kill signal, this must be a new message
        else:
            sessionID, messageContent, timeSent = self.unpackMessage(clientMessage) 

            try:
                
                if self.isMessageEncrypted(messageContent):
                    messageContent = self.decryptMessage(messageContent, self.keyMap[sessionID])

                self.sendToSocket(clientSocket, "Message received")
            
                username = self.usernameMap[sessionID]

                if messageContent == '/d':
                    self.msgRecvSocketMap[sessionID].close()
                    del self.msgRecvSocketMap[sessionID]
                    del self.usernameMap[sessionID]

                self.relayMessage(messageContent, username, timeSent)

            except KeyError:
                self.relayMessage(messageContent, sessionID, timeSent)   
            
            clientSocket.close()

            

    def relayMessage(self, messageContent, username, timeSent = None):
        #Send the message to all clients
        sessionsToRemove = []

        for sessionID, recvSocket in self.msgRecvSocketMap.items():
            try:

                #the /p command transmits a message in plaintext
                if messageContent.startswith("/p"):
                    encryptedMessage = messageContent
                else:
                    encryptedMessage = self.encryptMessage(messageContent, self.keyMap[sessionID])

                self.sendToSocket(recvSocket, self.packMessage(encryptedMessage, username, timeSent))
                
                #Wait for recv socket ok
                self.readFromSocket(recvSocket)
            except SocketError:
                print("Removing dead recv socket for %s" % sessionID)
                sessionsToRemove.append(sessionID)
                
        removedUsernames = []
        for sessionID in sessionsToRemove:
            self.msgRecvSocketMap[sessionID].close()
            removedUsernames.append(self.usernameMap[sessionID])
            del self.msgRecvSocketMap[sessionID]
            del self.usernameMap[sessionID]

        #relay a 'lost connection' message for each session lost
        for user in removedUsernames:
            #this is technically recursion
            self.relayMessage('/lc', user)

    def run(self):
        
        with socket(AF_INET, SOCK_STREAM) as serverSock:
            serverSock.bind((self.address, self.port))
            serverSock.listen(5)
            while True:
            
                clientSocket, clientAddress = serverSock.accept()
                try:
                    self.handleConnection(clientSocket, clientAddress)
                except Exception as ex:
                    print("Exception occurred!")
                    print("Type:", type(ex))
                    print("Args:", ex)


    #runs the server in a new thread
    def start(self):
        self.serverThread.start()

#TODO: Create a clean scheme for stopping a running server

if __name__ == "__main__":
    s = SecCLIChatServer('0.0.0.0')
    s.start()

    input("Press enter at any time to kill server")
    
