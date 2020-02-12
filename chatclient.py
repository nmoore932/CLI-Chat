#A SecCLIChat client
from basechat import SecCLIChatBase
from socket import socket, AF_INET, SOCK_STREAM, error as SocketError

from pushbuffer import PushBuffer
from threading import Thread, Event

class SecCLIChatClient(SecCLIChatBase):

    def printMessages(self):
        from datetime import datetime
        sortedMessages = sorted(self.messages.getNonNoneValues(), key = lambda x: x[2])
        for username, message, timeSent in sortedMessages:
            timeSentSTR = datetime.fromtimestamp(timeSent/1000).strftime('%d-%m-%Y %H:%M:%S')

            if message == "/c":
                print("<{}> {} connected".format(timeSentSTR, username))
            elif message == "/d":
                print("<{}> {} disconnected".format(timeSentSTR, username))
            elif message == "/lc":
                print("<{}> {} lost connection".format(timeSentSTR, username))
            elif message.startswith("/p"):
                print("<{}> <INSECURE> {}:  {}".format(timeSentSTR, username, message.lstrip('/p ')))
            else:
                print("<{}> {}:  {}".format(timeSentSTR, username, message))
    
    def redrawScreen(self):
        from os import system, name as osName
        system('cls' if osName == 'nt' else 'clear')
        self.printMessages()
        print("> ", end="", flush = True)

    #loop ends and socket is closed when killEvent is set
    def readMessagesLoop(self):
        while not self.killEvent.is_set():
            user, message, timestamp = self.unpackMessage(self.readFromSocket(self.recvSocket))
            
            if self.isMessageEncrypted(message):
                message = self.decryptMessage(message, self.sharedKey)

            self.messages.push((user, message, timestamp))

            self.sendToSocket(self.recvSocket, "ok")

            self.redrawScreen()

        self.killEvent.clear()

        self.recvSocket.close()
            
    def __init__(self, username, serverAddress = '127.0.0.1', serverPort = 7070):
        from uuid import uuid1
        from diffiehellman import generateKey, getPublicKey, getSharedKey

        if len(username) > 100:
            raise ValueError("Please enter a username less than 100 characters in length")
        else:
            self.username = username if username != '' else 'Anonymous'

        self.address = self.validateAddress(serverAddress)
        self.port = self.validatePort(serverPort)

        self.sessionID = str(uuid1())

        self.recvSocket = socket(AF_INET, SOCK_STREAM)
        self.recvSocket.connect((self.address, self.port))
        self.sendToSocket(self.recvSocket, self.username + ";" + self.sessionID)
        signonResponse = self.readFromSocket(self.recvSocket)
        print("Signon:", signonResponse if signonResponse != "RECV Socket registered" else "Connected!")

        privateKey = generateKey()
        publicKey = getPublicKey(privateKey)
        self.sendToSocket(self.recvSocket, str(publicKey))
        self.sharedKey = getSharedKey(privateKey, int(self.readFromSocket(self.recvSocket)))

        self.sendToSocket(self.recvSocket, "ok")

        self.messages = PushBuffer(25)

        self.killEvent = Event()
        self.readMessagesThread = Thread(target = self.readMessagesLoop, name = "readMessagesThread", daemon = True)
        self.readMessagesThread.start()

    def sendMessage(self, message):
        messageSocket = socket(AF_INET, SOCK_STREAM)

        messageSocket.connect((self.address, self.port))
        self.sendToSocket(messageSocket, self.packMessage(message, usernameOrSessionID = self.sessionID))
        #Wait for server ok
        self.readFromSocket(messageSocket)
        messageSocket.close()

    def sendEncryptedMessage(self, message):
        encryptedMessage = self.encryptMessage(message, self.sharedKey)
        self.sendMessage(encryptedMessage)
        

    def close(self):
        self.killEvent.set()



    
def chatUI():
    address = input("Enter server address: ")
    port = input("Enter server port (blank for default): ")
    username = input("Enter username: ")

    try:

        c = SecCLIChatClient(username, address if (address != 'localhost' and address != "")  else '127.0.0.1', int(port) if port != "" else 7070)
        while True:
            userResponse = input("> ")
            if userResponse == "/d" or userResponse == "\\d":
                print("Disconnecting...")
                c.sendEncryptedMessage("/d")
                break
            elif userResponse == "/c":
                c.sendEncryptedMessage("/c ")

            elif userResponse == "/lc":
                c.sendEncryptedMessage("/lc ")

            elif userResponse.startswith("/p") or userResponse.startswith("\\p"):
                c.sendMessage(userResponse.replace("\\p", "/p"))
            else:
                c.sendEncryptedMessage(userResponse)
    finally:
        if 'c' in locals():
            c.close()
        


if __name__ == '__main__':
    chatUI()