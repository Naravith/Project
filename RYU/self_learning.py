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
from collections import defaultdict
from ryu import utils

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

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser
        print("Object Switch {0} : {1}".format(switch.id, switch.__dict__))
        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch

            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)
        print("Switchs {0} Enter.\nDatapath_List :".format(self.switches))
        for i in self.datapath_list:
            print("Switch {0} -> {1}".format(i, self.datapath_list[i].__dict__))
        print("-" * 40)

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no
        print("s1 : {0}\ns2 : {1}".format(s1, s2))
        print("adj :", self.adjacency)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)
        print("Switch : {0} Connected".format(datapath.id))
        if self.check_first_dfs:
            self.check_first_dfs = 0
            self._get_paths()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        dst = eth.dst
        src = eth.src

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        if arp_pkt:
            self.logger.info("ARP processing")
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

        if ip_pkt:
            self.logger.info("IPv4 Processing")
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

    def _get_paths(self):
        topo = [
                [2, 3],
                [1, 3],
                [1, 2, 6],
                [5, 6],
                [4, 6],
                [3, 4, 5]
        ]
        for x in range(1, 7):
            for y in range(1, 7):
                if x != y:
                    key_link, mark, path = str(x) + '->' + str(y), [0] * 6, []
                    self.all_path.setdefault(key_link, {})
                    mark[x - 1] = 1
                    self._dfs(x, y, [x], topo, mark, path)
                    self.all_path[key_link] = sorted(path, key = len)

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
        self.logger.info("Flooding msg")

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