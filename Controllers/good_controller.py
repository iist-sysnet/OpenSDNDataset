from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ether_types
import threading
import networkx as nx
from prettytable import PrettyTable
import time
from ryu.lib.packet import arp
from ryu.lib import mac
from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
import pickle


class SimpleSwitch13(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.eth_ip = {}
        self.arp_table = {}
        self.sw = {}
        self.links = {}
        with open("/home/mininet/Controllers/topo.pkl", 'r') as pklfile:
            self.graph = pickle.load(pklfile)

        with open("/home/mininet/Controllers/links.pkl", 'r') as pklfile:
            self.links = pickle.load(pklfile)


    def get_topology(self):

        # graph = nx.Graph()
        # self.get_topology_data(1)
        # for i in range(1, len(self.links.keys()) + 1):
        #     graph.add_node('10.0.0.%d' % (i))
        # graph.add_nodes_from(self.links.keys())
        # for x in self.links.keys():
        #     for y in self.links[x].keys():
        #         graph.add_edge(x, y)
        # for i in range(len(self.links.keys())):
        #     graph.add_edge('10.0.0.%d' % (i+1), i+1)

        # return graph
        #self.get_topology_data(1)
        return self.graph

    def get_malicious_path(self, start, end):

        if(start in self.topology and end in self.topology):
            return nx.shortest_path(self.topology, start, end)
        else:
            return []

#    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        return
        switch_list = get_switch(self, None)
        switches=[switch.dp.id for switch in switch_list]
        links_list = get_link(self, None)
        #self.links=[(link.src.dpid,link.dst.dpid,{'port':link.src.port_no}) for link in links_list]
        
        for link in links_list:
            if link.src.dpid in self.links.keys():
                self.links[link.src.dpid][link.dst.dpid] = link.src.port_no
            else:
                self.links[link.src.dpid] = {}
                self.links[link.src.dpid][link.dst.dpid] = link.src.port_no
        #print self.links


    def send_set_config(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        req = ofp_parser.OFPSetConfig(datapath, ofp.OFPC_FRAG_NORMAL, 65535)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        print "switch Registered"
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.send_set_config(datapath)

        match = parser.OFPMatch(eth_type=0x0806, arp_tpa="10.0.2.3")
        actions = []
        self.add_flow(datapath, 10, match, actions)
        

    def add_flow(self, datapath, priority, match, actions,
                 buffer_id=None, idle=0, hard=0):

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle,
                                    hard_timeout=hard)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle, hard_timeout=hard)

        datapath.send_msg(mod)

    def is_ip(self, a):

        if(len(a.split('.')) == 4):
            return True
        return False

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        #print("Packet INNN!")
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.arp_table[arp_pkt.src_ip] = src  # ARP learning

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        self.topology = self.get_topology()
        
        print self.topology.nodes(), "is the topology!!!\n\n\n"

        
        if(dst not in self.eth_ip.keys()):
            self.eth_ip[dst] = dst

        if(src not in self.eth_ip.keys()):
            self.eth_ip[src] = src

        self.mac_to_port.setdefault(dpid, {})

        try:
            pktip = packet.Packet(msg.data)
            ip_pkt = pkt.get_protocol(ipv4.ipv4)
            self.dst_ip = ip_pkt.dst
            self.src_ip = ip_pkt.src
            self.eth_ip[dst] = self.dst_ip
            self.eth_ip[src] = self.src_ip

        except:
            self.dst_ip = "Z"
            self.src_ip = "Z"

        self.logger.info("packet in %s %s %s", self.eth_ip[src], self.eth_ip[dst], dpid)

        if(self.is_ip(self.eth_ip[dst]) and self.is_ip(self.eth_ip[src]) and self.dst_ip!="10.10.255.255"):

            sw_ip = datapath.address[1]
            sw_ip_str = '\033[93m' + str(dpid) + '\033[0m'

            ip_src = self.src_ip
            ip_dst = self.dst_ip

            if ip_dst != '10.10.255.255':
                ip_src_str = '\033[32m' + self.eth_ip[src] + '\033[0m'
                ip_dst_str = '\033[32m' + self.eth_ip[dst] + '\033[0m'
            else:
                ip_src_str = self.eth_ip[src]
                ip_dst_str = self.eth_ip[dst]

            t = PrettyTable(['Time', 'switch', 'eth_src', 'eth_dst', 'ip_src', 'ip_dst'])
            t.add_row([time.strftime('%X'), sw_ip_str, src, dst, ip_src_str, ip_dst_str])
            if ip_dst != '10.10.255.255':
                print t, '\n'

            if('10.0.' not in self.eth_ip[src]):
                print "Src wrong"
                path = self.get_malicious_path('10.0.0.2', self.eth_ip[dst])

            elif('10.0.' not in self.eth_ip[dst]):
                print "Dst wrong"
                path = self.get_malicious_path(self.eth_ip[src], '10.0.0.2')

            else:
                path = self.get_malicious_path("10.0.0.%d"%dpid, self.eth_ip[dst])
                #path = self.get_malicious_path(self.eth_ip[src], self.eth_ip[dst])

            if len(path) is not 0:
                print path, 'is the path!'

                if dpid not in path:
                    path.insert(0, dpid)
                if(dpid in path):
                    out_port = ofproto.OFPP_ALL
                    # try:
                    print path[path.index(dpid)+1]
                    if(len(str(path[path.index(dpid)+1])) < 4):
                        print self.links, "is the links"
                        print self.links[dpid]
                        print self.links[dpid][path[path.index(dpid)+1]]

                        out_port = self.links[dpid][path[path.index(dpid)+1]]

                        #pass
                    else:
                        if('10.0.' not in self.eth_ip[dst]):
                            return
                        out_port = len(self.links[dpid].keys())+1

                    print('Out port is set to %s' % out_port)
                    actions = [parser.OFPActionOutput(out_port)]
                    print "Packet Passed!"
                else:
                    actions = []
                    print 'Packet Dropped!'

                match = parser.OFPMatch(eth_dst=dst, eth_src=src)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 10, match, actions,
                                  msg.buffer_id, idle=20, hard=300)
                    return
                else:
                    self.add_flow(datapath, 10, match, actions,
                                  idle=20, hard=300)

                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                          in_port=in_port, actions=actions,
                                          data=data)
                datapath.send_msg(out)
                return

            else:
                return    

        if self.arp_handler(msg):  # 1:reply or drop;  0: flood
            return None

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        out_port = ofproto.OFPP_ALL

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def arp_handler(self, msg):

        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)

        if eth:
            eth_dst = eth.dst
            eth_src = eth.src

        # Break the loop for avoiding ARP broadcast storm
        if eth_dst == mac.BROADCAST_STR and arp_pkt:
            arp_dst_ip = arp_pkt.dst_ip

            print "This guy is requesting for %s"%(arp_dst_ip)
            if('10.0.0.' not in arp_dst_ip):
                return True
                
            if (datapath.id, eth_src, arp_dst_ip) in self.sw:
                if self.sw[(datapath.id, eth_src, arp_dst_ip)] != in_port:
                    datapath.send_packet_out(in_port=in_port, actions=[])
                    print "So Dropping"
                    return True
            else:
                self.sw[(datapath.id, eth_src, arp_dst_ip)] = in_port

        # Try to reply arp request
        if arp_pkt:
            hwtype = arp_pkt.hwtype
            proto = arp_pkt.proto
            hlen = arp_pkt.hlen
            plen = arp_pkt.plen
            opcode = arp_pkt.opcode
            arp_src_ip = arp_pkt.src_ip
            arp_dst_ip = arp_pkt.dst_ip

            if opcode == arp.ARP_REQUEST:
                if arp_dst_ip in self.arp_table:
                    actions = [parser.OFPActionOutput(in_port)]
                    ARP_Reply = packet.Packet()

                    ARP_Reply.add_protocol(ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth_src,
                        src=self.arp_table[arp_dst_ip]))
                    ARP_Reply.add_protocol(arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.arp_table[arp_dst_ip],
                        src_ip=arp_dst_ip,
                        dst_mac=eth_src,
                        dst_ip=arp_src_ip))

                    ARP_Reply.serialize()

                    out = parser.OFPPacketOut(
                        datapath=datapath,
                        buffer_id=ofproto.OFP_NO_BUFFER,
                        in_port=ofproto.OFPP_CONTROLLER,
                        actions=actions, data=ARP_Reply.data)
                    datapath.send_msg(out)
                    return True
        return False
