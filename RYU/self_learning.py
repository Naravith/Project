from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3, ether
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.topology import event
from ryu.topology.api import get_host
from ryu import utils
from collections import defaultdict
from operator import attrgetter

import time
import csv
import os
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
        self.link_for_DL = []
        self.best_path = {}
        self.monitor_thread = hub.spawn(self._TrafficMonitor)
        self.port_stat_links = defaultdict(list)
        self.csv_filename = {}
        self.queue_for_re_routing = [[], time.time()]

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
#self._re_routing(self.link_for_DL[random.randint(0, len(self.link_for_DL) - 1)])
    def _TrafficMonitor(self):
        while True:
            for datapath in self.datapath_for_del:
                for link in self.link_for_DL:
                    if datapath.id == link[0]:
                        self._PortStatReq(datapath, self.adjacency[link[0]][link[1]])
            if (time.time() - self.queue_for_re_routing[1]) > 10.0 and self.queue_for_re_routing[0] != []:
                self._re_routing(self.queue_for_re_routing[0])
                self.queue_for_re_routing[0], self.queue_for_re_routing[1] = [], time.time()
            hub.sleep(1)

    def _PortStatReq(self, datapath, port_no):
        #ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath=datapath, flags=0, port_no=port_no)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        msg = ev.msg
        port_stat_reply = msg.to_jsondict()
        port_stat = port_stat_reply['OFPPortStatsReply']['body'][0]['OFPPortStats']
        tx_p, tx_b = port_stat['tx_packets'], port_stat['tx_bytes']
        rx_p, rx_b = port_stat['rx_packets'], port_stat['rx_bytes']
        tmp = "S{0}-P{1}".format(msg.datapath.id, port_stat['port_no'])
        self.port_stat_links[tmp].append([tx_p, rx_p, tx_b, rx_b])

        '''
        if tmp not in self.port_stat_links:
            self.port_stat_links[tmp].append([tx_p, rx_p, tx_b, rx_b])
        else:
            #past_port_stat = self.port_stat_links[tmp].pop(0)
            self.port_stat_links[tmp].pop(0)
            self.port_stat_links[tmp].append([tx_p, rx_p, tx_b, rx_b])
            #self.port_stat_links[tmp].append([port_stat['tx_packets'] - past_port_stat[0], port_stat['rx_packets'] - past_port_stat[1], \
            # port_stat['tx_bytes'] - past_port_stat[2], port_stat['rx_bytes'] - past_port_stat[3]])
        '''

        for dst_switch, values in self.adjacency[msg.datapath.id].items():
            if values == port_stat['port_no']:
                filename = self.csv_filename["[{0}, {1}]".format(msg.datapath.id, dst_switch)]
                if not os.path.isfile(filename):
                    self._append_list_as_row(filename, ['Timestamp', 'Tx_Packet', 'Rx_Packet', 'BW_Utilization'])
                if len(self.port_stat_links[tmp]) == 1:
                    bw_util = (self.port_stat_links[tmp][0][2] + self.port_stat_links[tmp][0][3]) / 131072000
                    row_contents = [time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), self.port_stat_links[tmp][0][0], \
                        self.port_stat_links[tmp][0][1], bw_util]
                    if bw_util > 0.7 and ([msg.datapath.id, dst_switch] not in self.queue_for_re_routing[0]):
                        self.queue_for_re_routing[0].append([msg.datapath.id, dst_switch])
                elif len(self.port_stat_links[tmp]) == 2:
                    bw_util = ((self.port_stat_links[tmp][1][2] - self.port_stat_links[tmp][0][2]) + \
                                (self.port_stat_links[tmp][1][3] - self.port_stat_links[tmp][0][3])) / 131072000
                    row_contents = [time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), self.port_stat_links[tmp][1][0] - self.port_stat_links[tmp][0][0], \
                        self.port_stat_links[tmp][1][1] - self.port_stat_links[tmp][0][1], bw_util]
                    if bw_util > 0.7 and ([msg.datapath.id, dst_switch] not in self.queue_for_re_routing[0]):
                        self.queue_for_re_routing[0].append([msg.datapath.id, dst_switch])
                self._append_list_as_row(filename, row_contents)

        if msg.datapath.id == 1 and port_stat['port_no'] == 2:
            print("Switch : {0} || Port : {1}".format(msg.datapath.id, port_stat['port_no']))
            print("Time :", time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()))
            print("Tx : {0} packets | Rx:{1} packets".format(self.port_stat_links[tmp][0][0], self.port_stat_links[tmp][0][1]))
            if len(self.port_stat_links[tmp]) == 1:
                print("BW Utilization (100 Mbps) : {0} %".format((self.port_stat_links[tmp][0][2] + self.port_stat_links[tmp][0][3]) / 131072000 * 100))
            elif len(self.port_stat_links[tmp]) == 2:
                print("BW Utilization (100 Mbps) : {0} %".format(((self.port_stat_links[tmp][1][2] - self.port_stat_links[tmp][0][2]) + \
                                (self.port_stat_links[tmp][1][3] - self.port_stat_links[tmp][0][3])) / 131072000 * 100))
            print(self.port_stat_links)
            print("+" * 50)


        if len(self.port_stat_links[tmp]) == 2:
            self.port_stat_links[tmp].pop(0)
        

    def _append_list_as_row(self, file_name, list_of_elem):
        with open(file_name, 'a+', newline='') as write_obj:
            csv_writer = csv.writer(write_obj)
            csv_writer.writerow(list_of_elem)

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
        HOST = ev.host
        #print(type(ev))
        #print(ev)
        #print(ev.host)
        #print(ev.host.ipv4)
        #print(ev.host.mac)
        #print(ev.host.port)
        #print(ev.host.port.dpid)
        #print(ev.host.port.port_no)
        self.hosts[HOST.mac] = (HOST.port.dpid, HOST.port.port_no)
        self.host_faucet[HOST.port.dpid].append(HOST.port.port_no)

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
       
        #print("Switch : {0}\n{1}".format(datapath.id, datapath.__dict__))
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
        '''
        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)
        '''

        #print(time.time() - self.time_start)
        '''
        if (time.time() - self.time_start) > 40.0 and not self.check_first_dfs:
            #self.check_time = False
            self._re_routing(self.link_for_DL[random.randint(0, len(self.link_for_DL) - 1)])
            self.time_start = time.time()
        '''

        '''
        if not self.check_time:
            for dp in self.datapath_for_del:
                for out in self.adjacency[dp.id]:
                    self._del_flow(dp, self.adjacency[dp.id][out])
        '''

        if arp_pkt and self.check_time:
            #self.logger.info("ARP processing")
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            self.arp_table[src_ip] = src
            if arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    #dst_mac = self.arp_table[dst_ip]
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

    def _re_routing(self, banned=[]):
        print('+' * 50)
        print("Re-Routing Process :")
        for ban in banned:
            print("Banned Link Between Switch : {0} and Switch : {1}".format(ban[0], ban[1]))
        self.best_path ={}
        for path in self.all_path:
            tmp = self.all_path[path][0]
            for alternate_path in self.all_path[path]:
                for i in range(len(banned)):
                    if all(x in alternate_path for x in banned[i]) and abs(alternate_path.index(banned[i][1]) - alternate_path.index(banned[i][0])) == 1:
                        break
                else:
                    tmp = alternate_path
                    break
                '''
                if banned[0] not in alternate_path or banned[1] not in alternate_path:
                    tmp = alternate_path
                    break
                elif banned[0] in alternate_path and banned[1] in alternate_path and abs(alternate_path.index(banned[1]) - alternate_path.index(banned[0])) != 1:
                    tmp = alternate_path
                    break
                '''
            self.best_path.setdefault(path, {})
            self.best_path[path] = tmp
        
        for i in self.best_path:
            print(i, self.best_path[i])

        for dp in self.datapath_for_del:
            for out in self.adjacency[dp.id]:
                self._del_flow(dp, self.adjacency[dp.id][out])

        self.mac_to_port  = {}
        for i in self.hosts:
            self.mac_to_port.setdefault(self.hosts[i][0], {})
            self.mac_to_port[self.hosts[i][0]][i] = self.hosts[i][1]
        
        for src_mac in self.hosts:
            for dst_mac in self.hosts:
                if src_mac != dst_mac:
                    src_dpid, dst_dpid = self.hosts[src_mac][0], self.hosts[dst_mac][0]
                    tmp = self.best_path[str(src_dpid) + '->' + str(dst_dpid)]
                    for i in range(len(tmp) - 1):
                        self.mac_to_port[tmp[i]][dst_mac] = self.adjacency[tmp[i]][tmp[i + 1]]
        
        print("Re-Routing Seccess ! ! !")
        print('+' * 50)
        

    def _get_paths(self):
        cnt = 1
        for x in self.switches:
            for y in self.switches:
                if x != y:
                    if y in self.adjacency[x].keys() and [x, y] not in self.link_for_DL and [x, y][::-1] not in self.link_for_DL:
                        self.link_for_DL.append([x, y])
                        self.csv_filename.setdefault(str([x, y]), {})
                        self.csv_filename[str([x, y])] = "./link{0}.csv".format(cnt)
                        cnt += 1
                    key_link, mark, path = str(x) + '->' + str(y), [0] * len(self.switches), []
                    self.all_path.setdefault(key_link, {})
                    mark[x - 1] = 1
                    self._dfs(x, y, [x], self.topo, mark, path)
                    self.all_path[key_link] = sorted(path, key = len)
        '''
        print("Topology All Path :")
        for i in self.all_path:
            print(i, ":", self.all_path[i])
        '''

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
