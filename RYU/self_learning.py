from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.topology import event
from ryu.topology.api import get_host
from collections import defaultdict
from ryu import utils

import time
import inspect
import random

class SelfLearningBYLuxuss(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SelfLearningBYLuxuss, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_table = {}
        self.hosts = {}
        self.check_first_dfs = 1
        self.all_path = {}
        self.datapath_list = {}
        self.switches = []
        self.adjacency = defaultdict(dict)
        self.time_start = time.time()
        self.check_time = True
        self.datapath_for_del = []
        self.host_faucet = defaultdict(list)
        self.topo = []

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser
        #print("Object Switch {0} : {1}".format(switch.id, switch.__dict__))
        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.switches = sorted(self.switches)
            self.datapath_list[switch.id] = switch

            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)
        '''
        print("Switchs {0} Enter.\nDatapath_List :".format(self.switches))
        for i in self.datapath_list:
            print("Switch {0} -> {1}".format(i, self.datapath_list[i].__dict__))
        print("-" * 40)
        '''

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no
        #print("s1 : {0}\ns2 : {1}".format(s1, s2))
        #print("adj :", self.adjacency)

    @set_ev_cls(event.EventHostAdd, MAIN_DISPATCHER)
    def host_add_handler(self, ev):
        '''
        print(type(ev))
        print(ev)
        print(ev.host)
        print(ev.host.ipv4)
        print(ev.host.mac)
        print(ev.host.port)
        print(ev.host.port.dpid)
        print(ev.host.port.port_no)
        '''
        self.host_faucet[ev.host.port.dpid].append(ev.host.port.port_no)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)
        self.datapath_for_del.append(datapath)
        print("Switch : {0} Connected".format(datapath.id))

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        
        if self.check_first_dfs:
            sum_link1, sum_link2 = 0, 0
            for dp in self.datapath_for_del:
                for i in dp.ports:
                    if i != 4294967294 and (i not in self.host_faucet[dp.id]):
                        sum_link1 += 1
            for i in self.adjacency:
                sum_link2 += len(self.adjacency[i])
            if sum_link1 == sum_link2 and sum_link1 and sum_link2:
                for i in self.switches:
                    self.topo.append(sorted(self.adjacency[i]))
                self.check_first_dfs = 0
                self._get_paths()

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        dst = eth.dst
        src = eth.src

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        #print(time.time() - self.time_start)
        if (time.time() - self.time_start) > 10.0:
            #self.check_time = False
            print("Re-Routing")
            self._get_paths([random.randint(min(self.switches), max(self.switches))])
            self.time_start = time.time()

        if not self.check_time:
            for dp in self.datapath_for_del:
                for out in self.adjacency[dp.id]:
                    self._del_flow(dp, self.adjacency[dp.id][out])

        if arp_pkt and self.check_time:
            #self.logger.info("ARP processing")
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            self.arp_table[src_ip] = src
            if arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    dst_mac = self.arp_table[dst_ip]
                    #h1 = self.hosts[src]
                    #h2 = self.hosts[dst_mac]
                    if self._mac_learning(dpid, src, in_port):
                        self._arp_forwarding(msg, src_ip, dst_ip, eth)
                else:
                    if self._mac_learning(dpid, src, in_port):
                        self._arp_forwarding(msg, src_ip, dst_ip, eth)

            elif arp_pkt.opcode == arp.ARP_REPLY:
                #h1 = self.hosts[src]
                #h2 = self.hosts[dst]
                if self._mac_learning(dpid, src, in_port):
                    self._arp_forwarding(msg, src_ip, dst_ip, eth)

        if ip_pkt and self.check_time:
            #self.logger.info("IPv4 Processing")
            '''
            for i in range(1, 7):
                print("Switch {0} | {1} | {2}".format(i, i in self.mac_to_port, self.mac_to_port.get(i)))
            '''
            mac_to_port_table = self.mac_to_port.get(dpid)
            if mac_to_port_table:
                if eth.dst in mac_to_port_table:
                    out_port = mac_to_port_table[dst]
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    self._add_flow(datapath, 1, match, actions)
                    self._send_packet_out(datapath, msg.buffer_id, in_port,
                                         out_port, msg.data)
                else:
                    if self._mac_learning(dpid, src, in_port):
                        self._flood(msg)

    def _get_paths(self, banned=[]):
        for x in self.switches:
            for y in self.switches:
                if x != y:
                    key_link, mark, path = str(x) + '->' + str(y), [0] * len(self.switches), []
                    self.all_path.setdefault(key_link, {})
                    mark[x - 1] = 1
                    self._dfs(x, y, [x], self.topo, mark, path)
                    self.all_path[key_link] = sorted(path, key = len)

        if banned == []:
            print("All Path :")
            for i in self.all_path:
                print(i, self.all_path[i])
            print('+' * 50)
            return

        print("Banned Switch ", banned)
        for i in self.all_path:
            tmp = self.all_path[i][0]
            if banned != []:
                for j in self.all_path[i]:
                    if banned[0] not in j[1:-1]:
                        tmp = j
                        break
            print(i, "Bestpath is", tmp)
        print('+' * 50)
        

    def _dfs(self, start, end, k, topo, mark, path):
        if k[-1] == end:
            if len(k) == len(set(k)):
                path.append(k[:])
        for i in range(len(topo[start - 1])):
            if mark[topo[start - 1][i] - 1] == 0:
                mark[topo[start - 1][i] - 1] = 1
                k.append(topo[start - 1][i])
                self._dfs(topo[start - 1][i], end, k, topo, mark, path)
                k.pop()
                mark[topo[start - 1][i] - 1] = 0
    
    def _arp_forwarding(self, msg, src_ip, dst_ip, eth_pkt):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        out_port = self.mac_to_port[datapath.id].get(eth_pkt.dst)
        if out_port is not None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.dst,
                                    eth_type=eth_pkt.ethertype)
            actions = [parser.OFPActionOutput(out_port)]
            self._add_flow(datapath, 1, match, actions)
            self._send_packet_out(datapath, msg.buffer_id, in_port,
                                 out_port, msg.data)
        else:
            self._flood(msg)

    def _mac_learning(self, dpid, src_mac, in_port):
        self.mac_to_port.setdefault(dpid, {})
        if src_mac in self.mac_to_port[dpid]:
            if in_port != self.mac_to_port[dpid][src_mac]:
                return False
            return True
        else:
            self.mac_to_port[dpid][src_mac] = in_port
            return True

    def _flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                     ofproto.OFPP_CONTROLLER,
                                     ofproto.OFPP_FLOOD, msg.data)
        datapath.send_msg(out)
        #self.logger.info("Flooding msg")

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def _send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        #print("dpid : {0} | src : {1} | dst : {2}\nout : {3}".format(datapath.id, src_port, dst_port, out))
        if out:
            datapath.send_msg(out)

    def _add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _del_flow(self, dp, out):
        ofproto = dp.ofproto
        parser = dp.ofproto_parser
        
        mod = parser.OFPFlowMod(datapath=dp, cookie=0, priority=1,
                                out_port=out, out_group=ofproto.OFPG_ANY,
                                command=ofproto.OFPFC_DELETE)
        dp.send_msg(mod)
