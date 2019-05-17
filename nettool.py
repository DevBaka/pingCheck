#!/usr/bin/python3

import subprocess
import re
import _thread as thread
import time
import socket
import getopt
import argparse, sys

#TODO:
#regex to get // check domain
#regex to read ttl
#regex to read packet loss
#regex to read time
#multithreading for multiple pings
#get all ips/hosts from the network with subnets
#maybe a little gui to show all infos
#nice regex but didnt work  ^PING\b[^(]*\(([^)]*)\)\s([^.]*)\..*?^(\d+\sbytes).*?icmp_seq=(\d+).*?ttl=(\d+).*?time=(.*?ms).*?(\d+)\spackets\stransmitted.*?(\d+)\sreceived.*?(\d+%)\spacket\sloss.*?time\s(\d+ms).*?=\s([^\/]*)\/([^\/]*)\/([^\/]*)\/(.*?)\sms
#https://rubular.com/r/uEDoEZwY7U

#mittelwert vom packet loss und von der latenz(ms) berechnen lassen
#alle hosts im netzwerk gleichzeitig/durchgehend anpingen
#übersicht der hosts mit dem zuletzt gemessenen daten, sowie den durchschnittswerten



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
        out = str(p.communicate()[0])
        print(str(threadName) + " " + out)
        #m = re.findall(r'\s(?:www.)?(\w+.com)', str(p.communicate()[0]))
        domain = re.findall(r'\s(?:www.)?(\w+.(com|org|net|de))', out)
        #data = re.findall(r'^PING\b[^(]*\(([^)]*)\)\s([^.]*)\..*?^(\d+\sbytes).*?icmp_seq=(\d+).*?ttl=(\d+).*?time=(.*?ms).*?(\d+)\spackets\stransmitted.*?(\d+)\sreceived.*?(\d+%)\spacket\sloss.*?time\s(\d+ms).*?=\s([^\/]*)\/([^\/]*)\/([^\/]*)\/(.*?)\sms', out)
        #ttl = re.search(r'(?:ttl=[0-9]*)?', out)
        #ttl = re.findall(r'(?:time=([0-9]*.[0-9] ms))?', out)
        #print("domain: " + str(domain) + " ttl: " + str(ttl))
        #ttltime = re.findall(r'ttl=(\d+).*?rtt min\/avg\/max\/mdev = ([0-9.]+)\/', out)  # works
        #ptime = re.findall(r'ttl=(\d+).*?rtt min\/avg\/max\/mdev = ([0-9.]+)\/', out)
        #print("ttltime: " + str(ttltime)) #works
        #print("time: " + str(ptime))
        #data = re.findall(r"PING\b[^(]*\(([^)]*)\)\s([^.]*)\..*?^(\d+\sbytes).*?icmp_seq=(\d+).*?ttl=(\d+).*?time=(.*?ms).*?(\d+)\spackets\stransmitted.*?(\d+)\sreceived.*?(\d+%)\spacket\sloss.*?time\s(\d+ms).*?=\s([^\/]*)\/([^\/]*)\/([^\/]*)\/(.*?)\sms", out)
        icmp = re.findall(r'<?icmp_seq=(\d+)', out)
        ptime = re.findall(r'<?time=([0-9]*.[0-9])', out)
        plost = re.findall(r'<?([0-9]*%)', out)
        rip = re.findall(r'\d+\.\d+\.\d+\.\d+', out)
        print("time: " + str(ptime[0]) + "ms")
        print("icmp: " + str(icmp[0]))
        print("packet lost: " + str(plost[0]))
        print("ip: " + str(rip[0]))
        print("domain: " + str(domain[0][0]))
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

def main2():
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
            thread.start_new_thread(pingOnly, ("ping1", 3, "google.com"))
        if(key == "!port"):
            addr = input("domain")
            port = int(input("port"))
            print("port " + str(port) + " is " + str(portCheck(addr, port)) + " on host " + addr)


            #pingOnly(addr)
    #ping()

def main3(argv):
    domain = ""
    ipaddr = "0.0.0.0"
    subnet = "0"
    try:
        opts, args = getopt.getopt(argv,"di:s:",["domain=","ip=","subnet="])
    except getopt.GetoptError:
        print('nettool.py -h')
        sys.exit(2)

    for opt, arg in opts:
        if opt == "-h":
            help()
            sys.exit()
        elif opt in("-d", "--domain"):
            domain = arg
            print("domain: " + domain + " arg: " + str(arg))
            pingOnly("ping1", 1,domain)
        elif opt in ("-s", "--subnet"):
            subnet = arg
        elif opt in ("-i", "--ip"):
            ipaddr = arg


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--domain", help='set the Domain')
    parser.add_argument("--ip", help="set the ip")
    parser.add_argument("--subnet", help="set the subnet")
    #parser.add_argument("--help", help="show the help")

    args= parser.parse_args()
    print(args)
    print(sys)

    if args.domain != "":
        print(args.domain)
        pingOnly("ping1", 1, args.domain)


if __name__ == '__main__':
    #main()
    main3(sys.argv[1:])
    #main()

