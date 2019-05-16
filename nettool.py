#!/usr/bin/python3

import subprocess
import re
import _thread as thread
import time
import socket

#TODO:
#regex to get // check domain
#regex to read ttl
#regex to read packet loss
#regex to read time
#multithreading for multiple pings
#get all ips/hosts from the network with subnets
#maybe a little gui to show all infos

def help():
    print(" type !h to show this help")

def ping(address):
    print("test")
    p = subprocess.Popen(["ping", "www.google.de", "-c 1"], stdout = subprocess.PIPE)
    #m = re.search("/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/g", p.communicate()[0])
    #m = re.search("(((([A-Za-z0-9]+){1,63}\.)|(([A-Za-z0-9]+(\-)+[A-Za-z0-9]+){1,63}\.))+){1,255}", p.communicate()[0])
    #m.group(0)
    print(p.communicate()[0])
    print("regex: ")
    #print(m)

def pingOnly(threadName, delay, address):
    c = 0
    while c != 1:

        p = subprocess.Popen(["ping", address, "-c 1"], stdout = subprocess.PIPE)
        print(str(threadName) + " " + str(p.communicate()[0]))
        time.sleep(delay)

def portCheck(address, port):
    #REMOTE_SERVER = address
    try:
        host= socket.gethostbyname(address)
        s = socket.create_connection((host, port), 2)
        return True
    except:
        pass
    return False

def main():
    print("type !h to list all Commands")
    ping("google.de")

    rpings = 0
    key = input("command: ")
    while key != "!exit":
        key = input("command: ")
        if(key == "!h"):
            help()
        if(key == "!pingOnly"):
            addr = input("domain")
            rpings = rpings + 1
            #thread.start_new_thread(pingOnly, ("ping" + str(rpings),10,addr))
        if(key == "!tping"):
            thread.start_new_thread(pingOnly, ("ping2", 3, "www.devbaka.de"))
            thread.start_new_thread(pingOnly, ("ping1", 3, "www.google.de"))
        if(key == "!port"):
            addr = input("domain")
            port = int(input("port"))
            print("port " + str(port) + " is " + str(portCheck(addr, port)) + " on host " + addr)


            #pingOnly(addr)
    #ping()

if __name__ == '__main__':
    main()

