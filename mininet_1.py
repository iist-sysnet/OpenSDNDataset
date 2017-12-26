#!/usr/bin/python

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.cli import CLI
from mininet.node import Controller, RemoteController, OVSController
from mininet.node import OVSSwitch
import subprocess
import shlex
import threading
import time
import sys
import random as rd
import pickle
import networkx as nx
import pickle

lock = threading.Lock()

class TrafficGenerator(threading.Thread):

    def __init__(self):
        super(TrafficGenerator, self).__init__()
        self.procs = []
        self.count = 1
        self.over = True

    def perform(self, one, two):
        pass

    def run(self):

        global hosts
        sw = hosts[:]
        print sw
        done = []
        while(True):

            rd.shuffle(sw)
            if((sw[0], sw[1]) not in done):
                self.perform(sw[0], sw[1])
                time.sleep(0.1)
                #done.append((sw[0], sw[1]))
            if(len(done) == (len(sw)*(len(sw) - 1))):
                self.over = False

class PingTraffic(TrafficGenerator):

    def __init__(self):
        super(PingTraffic, self).__init__()

    def perform(self, one, two):
        global net, lock

        # print "Pinging#%d %s to %s" % (self.count, one, two)
        # cmd = "sudo ITGSend -a %s -E 1000 -T ICMP -z 1000"% ('10.0.0.'+two[1:])
        cmd = "ping %s -w 1 &" % ('10.0.0.'+two[1:])
        lock.acquire()
        net.get(one).cmd(cmd)
        lock.release()
        self.count += 1
        #time.sleep(0.5)


class VoIPTraffic(TrafficGenerator):

    def __init__(self):
        super(VoIPTraffic, self).__init__()

    def perform(self, one, two):
        global net, lock

        # print "Pinging#%d %s to %s" % (self.count, one, two)
        cmd = "ITGSend -a %s -E 1000 -z 1000 VoIP &" % ('10.0.0.'+two[1:])
        lock.acquire()
        net.get(one).cmd(cmd)
        lock.release()
        self.count += 1
        #time.sleep(0.1)


class UDPTraffic(TrafficGenerator):

    def __init__(self):
        super(UDPTraffic, self).__init__()

    def perform(self, one, two):
        global net, lock

        # print "Pinging#%d %s to %s" % (self.count, one, two)
        #cmd = "ITGSend -a %s -E 1000 -T UDP -z 1000" % ('10.0.0.'+two[1:])
        cmd = "iperf -c %s -y C -p %d -u -n 1000 &" % ('10.0.0.'+two[1:], 6000+int(str(two)[1:]))
        lock.acquire()
        net.get(one).cmd(cmd)
        lock.release()
        self.count += 1
        #time.sleep(0.1)


class DNSTraffic(TrafficGenerator):

    def __init__(self):
        super(DNSTraffic, self).__init__()

    def perform(self, one, two):
        global net, lock

        # print "Pinging#%d %s to %s" % (self.count, one, two)
        cmd = "ITGSend -a %s -E 1000 -z 1000 DNS &" % ('10.0.0.'+two[1:])
        #cmd = "iperf -c %s -y C -p %d -n 1000 &" % ('10.0.0.'+two[1:], 5000+int(str(two)[1:]))
        lock.acquire()
        net.get(one).cmd(cmd)
        lock.release()
        self.count += 1
        #time.sleep(0.5)


class HttpTraffic(TrafficGenerator):

    def __init__(self):
        super(HttpTraffic, self).__init__()

    def perform(self, one, two):
        global net, lock

        # print "Iperf UDP#%d %s to %s" % (self.count, one, two)
        cmd = "wget http://%s:8080/test" % ('10.0.0.'+two[1:])
        lock.acquire()
        net.get(one).cmd(cmd)
        lock.release()
        self.count += 1
        #time.sleep(0.1)


class TCPTraffic(TrafficGenerator):

    def __init__(self):
        super(TCPTraffic, self).__init__()

    def perform(self, one, two):
        global net, lock

        # print "Iperf TCP#%d %s to %s" % (self.count, one, two)
        cmd = "iperf -c %s -y C -p %d -n 1000 &" % ('10.0.0.'+two[1:], 5000+int(str(two)[1:]))
        #cmd = "sudo ITGSend -a %s -E 1000 -T TCP -z 1500" % ('10.0.0.'+two[1:])
        lock.acquire()
        net.get(one).cmd(cmd)
        lock.release()
        self.count += 1
        #time.sleep(0.1)

class DataLog(threading.Thread):

    # Constructor
    def __init__(self, path):
        super(DataLog, self).__init__()
        global topology
        #print topology
        self.path = path
        with open("%s/topo.pkl" % (self.path), "w") as f:
            pickle.dump(topology, f)
        time.sleep(2)

    def run(self):
        global net
        start = time.time()
        while(True):
            for s in switches:
                data = net.get(s).cmd('ovs-ofctl dump-flows -O OpenFlow13 %s' % (s))
                with open('%s/%s' % (self.path, s), 'a+') as f:
                    f.write(str(time.time() - start) + "\n")
                    f.write(data+'\n')
            time.sleep(5)


class CustomTopo(Topo):

    "Single switch connected to n hosts."
    def build(self):

        global switches, hosts, topology, num_switches

        graph = nx.Graph()
        rd.seed()
        check = {}
        num_switches = rd.randint(min_nodes, max_nodes)

        port_counter = {}
        plinks = {}
        
        if(num_switches % 2 != 0):
            num_switches += 1
            
        for i in range(num_switches):
            self.addSwitch('s%d' % (i+1))
            switches.append('s%d' % (i+1))
            topology['s%d' % (i+1)] = {}
            graph.add_node(i+1)

        for i in range(1, num_switches+1):
            graph.add_node("10.0.0.%d"%i)
            graph.add_edge("10.0.0.%d"%i, i)

        for i in switches:
            for j in switches:
                topology[i][j] = 0

        links = []
        for i in range(num_switches-2):
            for j in range(i+2, num_switches):
                links.append(['s%d'%(i+1), 's%d'%(j+1)])

        mesh_degree = degree_mesh_min + (rd.random() * (degree_mesh_max - degree_mesh_min))

        for i in range(num_switches-1):
            self.addLink('s%d' % (i+1), 's%d' % (i+2))
            topology['s%d' % (i+1)]['s%d' % (i+2)] = 1
            topology['s%d' % (i+2)]['s%d' % (i+1)] = 1
            
            cur_link = [i+1, i+2]
            if cur_link[0] not in plinks.keys():
                plinks[cur_link[0]] = {}
            if(cur_link[0] not in port_counter.keys()):
                port_counter[cur_link[0]] = 1
            plinks[cur_link[0]][cur_link[1]] = port_counter[cur_link[0]]
            port_counter[cur_link[0]] += 1

            if cur_link[1] not in plinks.keys():
                plinks[cur_link[1]] = {}
            if(cur_link[1] not in port_counter.keys()):
                port_counter[cur_link[1]] = 1
            plinks[cur_link[1]][cur_link[0]] = port_counter[cur_link[1]]
            port_counter[cur_link[1]] += 1
            
            graph.add_edge(i+1, i+2)

        for i in range(int(mesh_degree * len(links))):
            cur_link = rd.choice(links)
            for j in range(2):
                if(cur_link[j] in check):
                    check[cur_link[j]] += 1
                else:
                    check[cur_link[j]] = 1
            if(check[cur_link[0]] > 2 or check[cur_link[1]] > 2):
                continue
            del links[links.index(cur_link)]
            topology[cur_link[0]][cur_link[1]] = 1
            topology[cur_link[1]][cur_link[0]] = 1

            self.addLink(cur_link[0], cur_link[1])

            cur_link[0] = int(cur_link[0][1:])
            cur_link[1] = int(cur_link[1][1:])

            graph.add_edge(cur_link[0], cur_link[1])
            if cur_link[0] not in plinks.keys():
                plinks[cur_link[0]] = {}
            if(cur_link[0] not in port_counter.keys()):
                port_counter[cur_link[0]] = 1
            plinks[cur_link[0]][cur_link[1]] = port_counter[cur_link[0]]
            port_counter[cur_link[0]] += 1

            if cur_link[1] not in plinks.keys():
                plinks[cur_link[1]] = {}
            if(cur_link[1] not in port_counter.keys()):
                port_counter[cur_link[1]] = 1
            plinks[cur_link[1]][cur_link[0]] = port_counter[cur_link[1]]
            port_counter[cur_link[1]] += 1

        # Python's range(N) generates 0..N-1
        for h in range(len(switches)):
            host1 = self.addHost('h%s' % (h+1))
            hosts.append(host1)
            self.addLink(host1, switches[h])

        with open("/home/mininet/Controllers/topo.pkl", "w") as pklfile:
            pickle.dump(graph, pklfile)

        with open("/home/mininet/Controllers/links.pkl", "w") as pklfile:
            pickle.dump(plinks, pklfile)

        with open("/home/mininet/global.pkl", "w") as pklfile:
            pickle.dump((switches, hosts, topology, num_switches), pklfile)

        print "Topology dumped successfully"
        #print topology


topos = {'mytopo': (lambda: CustomTopo())}


def simpleTest():

    global switches, hosts, net, num_switches
    "Create and test a simple network"

    if(int(sys.argv[2]) % 2 == 1):
        topo = CustomTopo()
        
        with open("mini_topo", 'w') as f:
            pickle.dump(topo, f)
            print "Topo dumped successfully!!"

    else:
        with open("mini_topo", 'r') as f:
            topo = pickle.load(f)
            
        with open("global.pkl", 'r') as f:
            switches, hosts, topology, num_switches = pickle.load(f)
            
    net = Mininet(topo=topo, controller=None)

    for switch in switches:
        for intf in net.get(switch).intfList():
            port = net.get(switch).ports[ intf ]
            print intf, switch, port
        
    path = sys.argv[1]
    # print "Dumping host connections"
    dumpNodeConnections(net.hosts)

    try:
        net.start()

        # Manually set switches to use OF1.3 and a custom controller of choice
        ind = 0
        for switch in switches:

            ind += 1
            net.get(switch).cmd('ovs-vsctl set bridge %s \
            protocols=OpenFlow13' % (switch))
            #net.get(switch).cmd('ovs-vsctl set bridge %s stp-enable=true' % switch)

            #net.get(switch).cmd('ovs-vsctl set-controller %s \
            #tcp:127.0.0.1:6634 connection-mode=out-of-band' % (switch))
            
            if(ind % 2 == 0):
                net.get(switch).cmd('ovs-vsctl set-controller %s \
                tcp:127.0.0.1:6634 connection-mode=out-of-band' % (switch))
            else:
                net.get(switch).cmd('ovs-vsctl set-controller %s \
                tcp:127.0.0.1:6636 connection-mode=out-of-band' % (switch))

            time.sleep(0.5)

            print "Switch Connected to controller!"

        #net.waitConnected()
        net.staticArp()

        for host in hosts:


            net.get(host).cmd("route add default gw %s" % ('10.0.0.2'))
            net.get(host).cmd("iperf -s -u -D -p %d &" % (6000 + int(str(switch)[1:])))
#            time.sleep(0.1)
            net.get(host).cmd("iperf -s -D -p %d &" % (5000 + int(str(switch)[1:])))
            net.get(host).cmd("sudo ITGRecv &")
            net.get(host).cmd("ruby -run -e httpd . -p 8080 &")
            #print "Started service in this host!!"
            #time.sleep(0.1)

        
        #CLI(net)
        print("All switches connected to all controllers!")
        flow_thread_log = DataLog(path)
        tcp = TCPTraffic()
        udp = UDPTraffic()
        ping = PingTraffic()
        voip = VoIPTraffic()
        dns = DNSTraffic()
        http = HttpTraffic()
        
        flow_thread_log.daemon = True

        tcp.daemon = True
        udp.daemon = True
        ping.daemon = True
        voip.daemon = True
        dns.daemon = True
        http.daemon = True

        tcp.start()
        udp.start()
        ping.start()
        voip.start()
        dns.start()
        #http.start()

        flow_thread_log.start()

        print "Starting the traffic now.."
        t = 0
        time_out = 25
        while t < time_out and (tcp.over or udp.over or ping.over or http.over or voip.over or dns.over):
            time.sleep(0.1)  # (comment 1)
            t += 0.1
        if(t<time_out):
            print("Operations completed before 20 seconds, terminating")
        else:
            print "Terminating the traffic after 20 seconds"
        #while(True):
        #net.pingAll()
        #time.sleep(1)

    finally:
        net.stop()


if __name__ == '__main__':
    # Tell mininet to print useful information
    # setLogLevel('info')
    switches = []
    hosts = []
    min_nodes = 5
    max_nodes = 25
    degree_mesh_min = 0.3
    degree_mesh_max = 0.9
    net = None
    topology = {}
    simpleTest()
