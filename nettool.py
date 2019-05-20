#!/usr/bin/python3

import subprocess
import multiprocessing.dummy
import multiprocessing
import re
import _thread as thread
import time
import socket
import getopt
import argparse, sys
import threading

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
#regex test: https://rubular.com/r/uEDoEZwY7U
#curses: https://de.wikibooks.org/wiki/Python_unter_Linux:_Curses
#nmap: https://www.programcreek.com/python/example/92225/nmap.PortScanner

#mittelwert vom packet loss und von der latenz(ms) berechnen lassen
#alle hosts im netzwerk gleichzeitig/durchgehend anpingen
#übersicht der hosts mit dem zuletzt gemessenen daten, sowie den durchschnittswerten


ips = []
#data = [{"id":0, "ip":"here stands ips", "icmp":"icmp data", "ptime":"ptime data", "plost": "plost data", "rip": "rip data"},]
data = {}

def help():
    print(" type !h to show this help")

def pingOLD(address):
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
        try:
            domain = re.findall(r'\s(?:www.)?(\w+.(com|org|net|de))', out)
            print("domain: " + str(domain[0][0]))
        except:
            print("no domain vorhanden")
        time.sleep(delay)

def ping(threadName, delay, address, id):
    #time.sleep(3)
    t = 0
    c = 0
    while c != 1:
        time.sleep(1.5)
        t = t + 1
        p = subprocess.Popen(["ping", address, "-c 1"], stdout = subprocess.PIPE)
        out = str(p.communicate()[0])
        #print(str(threadName) + " " + out)
        icmp = re.findall(r'<?icmp_seq=(\d+)', out)
        ptime = re.findall(r'<?time=([0-9]*.[0-9])', out)
        plost = re.findall(r'<?([0-9]*%)', out)
        rip = re.findall(r'\d+\.\d+\.\d+\.\d+', out)

        #print("time: " + str(ptime[0]) + "ms")
        #print("icmp: " + str(icmp[0]))
        #print("packet lost: " + str(plost[0]))
        #print("ip: " + str(rip[0]))

        try:
            domain = re.findall(r'\s(?:www.)?(\w+.(com|org|net|de))', out)
            #print("domain: " + str(domain[0][0]))
            #data[id][t] = str(t), str(icmp), str(ptime), str(plost), str(rip), str(domain[0][0])
            #data[id][t] = str(t), str(icmp), str(ptime), str(rip)
            #data.extend(id, [t, icmp, ptime, rip])
            data[address] = str(t) + str(icmp) + str(ptime) + str(plost) + str(rip) + str(domain[0][0])

        except:
            #print("no domain vorhanden")
            #data[id][t] = str(t), str(icmp), str(ptime), str(plost), str(rip)
            #data.extend(id,[t,icmp,ptime,rip])
            data[address] = str(t) + str(icmp) + str(ptime) + str(plost) + str(rip)
        #time.sleep(delay)

#def ping()

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
    #ping("google.de")

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

def getIPS(network, start, end):
    for ping in range(start, end):
        address = network + str(ping)
        res = subprocess.call(['ping', '-c', '1', address])
        if res == 0:
            print("ping to", address, "OK")
            ips.append(address)
        elif res == 2:
            print("no response from", address)
        else:
            print("ping to", address, "failed!")

def getPing(ip):
    success = subprocess.call(['ping', '-c', '1', ip])
    if success:
        print("{} responded".format(ip))
        #ips.append(ip)
    else:
        print("{} did not respond".format(ip))
        ips.append(ip)
        #data.append(())
    return success

def ping_range(network,start,end):
    num_threads = 4 * multiprocessing.cpu_count()
    p = multiprocessing.dummy.Pool(num_threads)
    p.map(getPing, [network + str(x) for x in range(start,end)])
    #ips.append(network + str(x))

def printData():
    r = 0
    while r != 1:
        print("data: " + str(data))
        print("len data: " + str(len(data)))
        print("len ips: " + str(len(ips)))
        #print(str(data))
        #for i in range(len(data)):
        #    #print("Data" + str(i) + ": " + str(data[]) + ":" + str(data[i][1]))
        #    time.sleep(1)
        #    for c in i:
        #        #print("data: " + str(data[i]))
        #        print(c, end= " ")
        #        time.sleep(1)
        #print("data: " + str(data))
        time.sleep(5)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--domain", help='set the Domain')
    parser.add_argument("-d", help='set the Domain')
    parser.add_argument("--ip", help="set the ip")
    parser.add_argument("--subnet", help="set the subnet")
    parser.add_argument("-p", help='start Ping')
    #parser.add_argument("--help", help="show the help")

    args= parser.parse_args()
    print(args)
    print(sys)

    if str(args.domain) != "None":
        print(args.domain)
        pingOnly("ping1", 1, args.domain)

    if str(args.d) != "None":
        print(args.d)
        pingOnly("ping2", 1, args.d)

    if str(args.ip) != "None":
        print(args.ip)
        #getIPS(str(args.ip),0,255)
        #thread.start_new_thread(getIPS, (str(args.ip), 0,50))
        #thread.start_new_thread(getIPS, (str(args.ip), 51,100))
        #thread.start_new_thread(getIPS, (str(args.ip), 101,150))
        #thread.start_new_thread(getIPS, (str(args.ip), 151,200))
        #thread.start_new_thread(getIPS, (str(args.ip), 201,255))
        ping_range(str(args.ip),0,255)
        print("ips: " + str(ips))
        print("args.p: " + str(args.p))
        print("some ip: " + str(ips[4]) + " len: " + str(len(ips)))
        if str(args.p) != "None":
            for i in range(0,len(ips)):
                time.sleep(1)
                #pingOnly("ping" + str(i), 1, str(ips[i]))
                print("ping ip: " + str(ips[i]))
                #thread.start_new_thread(ping, ("ping" + str(i), 1, str(ips[i])))
                #thread.start_new_thread(pingOnly, ("ping" + str(i), 1, str(ips[i])))
                t1 = threading.Thread(target=ping, args=("ping" + str(i), 1, str(ips[i]), i))
                t1.start()

            t2 = threading.Thread(target=printData)
            t2.start()


if __name__ == '__main__':
    #main()
   #main3(sys.argv[1:])
    main()

