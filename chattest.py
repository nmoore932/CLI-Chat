#A test script that launches a SecCLIChat server and client
from multiprocessing import Process, Value
from chatserver import SecCLIChatServer
from chatclient import SecCLIChatClient, chatUI
from socket import socket
from time import sleep


if __name__ == "__main__":

    s = SecCLIChatServer('0.0.0.0')
    s.start()
    chatUI()

        
    