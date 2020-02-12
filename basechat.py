#A base class for both chat servers and clients
#All methods are classmethods or staticmethods so you can use them on their own if you'd like
#This probably could have been a module and not a class but abusing inheritance is more fun.

class SecCLIChatBase:

    BUFFER_SIZE = 4096

    @classmethod
    def getBufferSize(cls):
        return cls.BUFFER_SIZE

    #constructor does nothing
    def __init__(self):
        pass

    #returns true if and only if IPv4addr fits the format for an IPV4 address (Four octets seperated by the . character)
    @staticmethod
    def isIPv4(IPv4addr):

        #The correct way to tell if a given string matches a pattern is by using a regex, but I can't remember how
        # to write them off the top of my head

        #255.255.255.255 is the longest possible IPv4 address and is 15 characters long
        if len(IPv4addr) > 15:
            return False
        
        splitAddr = IPv4addr.split('.')
        #If there aren't exactly 4 octets, it is invalid
        if len(splitAddr) != 4:
            return False
        
        for octet in splitAddr:
            try:
                octetValue = int(octet)
            #ValueError is raised when a string can't be converted to an integer
            except ValueError:
                return False
            if octetValue > 255 or octetValue < 0: 
                return False

        return True

    #Raises an exception if an invalid entry is given for ipAddr
    @classmethod
    def validateAddress(cls, ipAddr):
        if not cls.isIPv4(ipAddr):
            raise ValueError("Invalid IP address: {}\nPlease use IPv4 addressing".format(ipAddr))
        else:
            return ipAddr
    
    #Turns a regular string into a netstring 
    #(a string prefixed with its length and formatted for socket transport)
    @staticmethod
    def toNetstring(regString):
        length = len(regString)

        return "{0}:{1}".format(length, regString).encode()
    
    #Turns a netstring into a regular string and returns the defined length 
    # (the actual message recieved may be shorter than the defined length; this indicates that
    # another socket read is needed)
    @staticmethod
    def fromNetstring(netstring):
        netstring = netstring.decode()
        #The index of the colon separating the length from the string
        indexOfColon = netstring.find(':')
        #Normally I'd use netstring.split, but there might be other colons in the string
        #The solution then is to split based on the index of the first colon, 
        # which must be the length/string seperator
        
        length = int(netstring[:indexOfColon])
        string = netstring[indexOfColon + 1 :]
        return (length, string)

    @staticmethod
    def isValidPort(portNumber, hideWarning = False):
        if isinstance(portNumber, int):
            
            if portNumber < 0:
                return False

            elif portNumber <= 1023:
                if not hideWarning:
                    print("WARNING: A port number of {} is likely already reserved but might work anyway".format(portNumber))
                    
                return True
            elif portNumber > 65535:
                return False

            return True
        else:
            return False
            
    @classmethod
    def validatePort(cls, portNumber):
        if not cls.isValidPort(portNumber):
            raise ValueError("Port number {} is invalid; please choose a number between 0 and 65535 inclusive".format(portNumber))
        else:
            return portNumber
        

    @staticmethod
    def packMessage(message, usernameOrSessionID, timeSent = None):
        from time import time

        if timeSent == None:
            #Set the timeSent to an integer number of miliseconds since the UNIX epoch
            timeSent = int(time() * 1000)
        
        #Escape " and ; characters
        sanitizedMessage = message.replace('\"','\\\"').replace(";", "\\;")

        sanitizedUsername = usernameOrSessionID.replace('\"','\\\"').replace(";", "\\;")
        return 'u="%s"m="%s"t="%d"' % (sanitizedUsername, sanitizedMessage, timeSent)

    #Unpacks a message in the form u="<username>"m="<message>"t="<timeSent>"
    #Un-escapes " and ; characters in both usernames and messages
    @staticmethod
    def unpackMessage(message):
        from re import match
        usernamePattern = r'u="(.*)"m="(.*)"t="(-?\d+)"'
    
        patternMatch = match(usernamePattern, message)

        if patternMatch != None:
            username, messageContent, timeSent = patternMatch.group(1, 2, 3)
            
            #username might be none, so we ensure it is instead set to an empty string
            if username == None: username = ""
            
            #Replace escaped quote characters with standard quotes
            username = username.replace('\\\"','\"').replace("\\;", ";" )
            messageContent = messageContent.replace('\\\"','\"').replace("\\;", ";" )
            timeSent = int(timeSent)

            return (username if username != '' else "Anonymous", messageContent, timeSent)
        
        #If the message doesn't fit the pattern, treat it as an anonymous plaintext message
        else:
            return ('Anonymous', message, 0)

    @classmethod
    def readFromSocket(cls, targetSocket):
        import inspect
        from re import compile
        pattern = compile(r'\d+:')

        recvdText = b""

        while not pattern.match(recvdText.decode()):
            recvdText += targetSocket.recv(cls.getBufferSize())

        msgLength, message = cls.fromNetstring(recvdText)
        while len(message) < msgLength:
            message += targetSocket.recv(cls.getBufferSize()).decode()

        return message

    @classmethod
    def sendToSocket(cls, targetSocket, messageToSend):

        netMessage = cls.toNetstring(messageToSend)
        sentBytes = 0
        while sentBytes < len(netMessage):
            sentBytes += targetSocket.send(netMessage[sentBytes:])

    #Returns a string encrypted using AES with the given key. 
    #The string contains all information (sans the shared key) needed to verify and decrypt the message
    @staticmethod
    def encryptMessage(message, sharedKey):
        from Cryptodome.Cipher import AES
        cipher = AES.new(sharedKey, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))

        packedCiphertext = "{},{},{}".format(nonce.hex(), ciphertext.hex(), tag.hex())
        return packedCiphertext

    @staticmethod
    def decryptMessage(packedCiphertext, sharedKey):
        from Cryptodome.Cipher import AES

        hexNonce, hexCiphertext, hexTag = packedCiphertext.split(",") 

        nonce = bytes.fromhex(hexNonce)
        ciphertext = bytes.fromhex(hexCiphertext)
        tag = bytes.fromhex(hexTag)

        cipher = AES.new(sharedKey, AES.MODE_EAX, nonce = nonce)

        message = cipher.decrypt(ciphertext).decode('utf-8')

        try:
            cipher.verify(tag)
        except ValueError:
            return "Invalid Message"
        else:
            return message
    
    #Uses a regex to determine if a given message is a packed encrypted message
    @staticmethod
    def isMessageEncrypted(message):
        from re import match
        pattern = r"[0-9a-f]{32},[0-9a-f]+,[0-9a-f]{32}"
        return bool(match(pattern, message))

if __name__ == "__main__":
    from diffiehellman import generateKey, getPublicKey, getSharedKey

    key1 = generateKey()
    key2 = generateKey()

    pubKey1 = getPublicKey(key1)
    pubKey2 = getPublicKey(key2)

    sharedKey = getSharedKey(key1, pubKey2)
    
    en = SecCLIChatBase.encryptMessage("super secret" * 200, sharedKey)
    print(en)


    de = SecCLIChatBase.decryptMessage(en, sharedKey)
    print(de)
        

    