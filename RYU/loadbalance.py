from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import ether_types
from ryu.lib import mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event
from ryu.lib import hub

from collections import defaultdict
from operator import itemgetter

import os
import random
import time
import csv
import inspect
from random import randint

# Cisco Reference bandwidth = 10 Mbps
REFERENCE_BW = 10000000

DEFAULT_BW = 10000000

MAX_PATHS = 2

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.group_ids = []
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))
        self.monitor_thread = hub.spawn(self._TrafficMonitor)
        self.datapath_for_del = []
        self.check_first_dfs = 1
        self.host_faucet = defaultdict(list)
        self.Hosts_add = {}
        self.topo = []
        self.link_for_DL = []
        self.csv_filename = {}
        self.all_path = {}
        self.flow_stat_links = defaultdict(list)
        self.flow_timestamp = defaultdict(list)
        self.port_stat_links = defaultdict(list)
        self.time_start = time.time()
        
    def _TrafficMonitor(self):
        while True:
            for datapath in self.datapath_for_del:
                if (time.time() - self.time_start) > 15:
                    self._FlowStatReq(datapath)
                for link in self.link_for_DL:
                    if datapath.id == link[0]:
                        self._PortStatReq(datapath, self.adjacency[link[0]][link[1]])
            '''
            if (time.time() - self.queue_for_re_routing[1]) > 20.0:
                if self.queue_for_re_routing[0] != []:
                    self._re_routing(self.queue_for_re_routing[0])
                    self.queue_for_re_routing[0], self.queue_for_re_routing[1] = [], time.time()
                    self.print_bw_util = []
            else:
                self.queue_for_re_routing[0] = []
                self.print_bw_util = []
            '''
            
            
            hub.sleep(1)

    def _PortStatReq(self, datapath, port_no):
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath=datapath, flags=0, port_no=port_no)
        datapath.send_msg(req)

    def _FlowStatReq(self, datapath):
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        msg = ev.msg

        flow_stat_reply = msg.to_jsondict()
        sum_bytes = {}
        sum_pkts = {}

        for i in self.Hosts_add.keys():
            sum_bytes[i] = 0
            sum_pkts[i] = 0

        for i in flow_stat_reply['OFPFlowStatsReply']['body']:
            if i['OFPFlowStats']['match']['OFPMatch']['oxm_fields'] != []:
                
                out_port = i['OFPFlowStats']['instructions'][0]['OFPInstructionActions']['actions'][0]['OFPActionOutput']['port']
                byte_count = i['OFPFlowStats']['byte_count']
                pkt_count = i['OFPFlowStats']['packet_count']
                in_port = -1
                eth_dst = -1
                eth_type = -1

                for j in i['OFPFlowStats']['match']['OFPMatch']['oxm_fields']:
                    if j['OXMTlv']['field'] == 'in_port':
                        in_port = j['OXMTlv']['value']
                    elif j['OXMTlv']['field'] == 'eth_dst': 
                        eth_dst = j['OXMTlv']['value']
                    elif j['OXMTlv']['field'] == 'eth_type':
                        eth_type = j['OXMTlv']['value']
                
                if eth_type not in [2054, 35020]:
                    for host_port in self.host_faucet[ev.msg.datapath.id]:
                        if out_port == host_port:
                            sum_bytes[eth_dst] += byte_count
                            sum_pkts[eth_dst] += pkt_count
        
        for i in [k for k, v in self.Hosts_add.items() if v[0] == ev.msg.datapath.id]:
            tmp = "HOST-{0}".format(i)
            self.flow_stat_links[tmp].append([sum_bytes[i], sum_pkts[i], time.time()])
            while len(self.flow_stat_links[tmp]) >= 3:
                self.flow_stat_links[tmp].pop(0)
            
            if len(self.flow_stat_links[tmp]) == 2:
                if (self.flow_stat_links[tmp][1][0] - self.flow_stat_links[tmp][0][0]) > 10000:
                    if (i not in self.flow_timestamp) or (len(self.flow_timestamp[i]) == 0):
                        self.flow_timestamp[i].append(self.flow_stat_links[tmp][0].copy())
                else:
                    throughput = -1
                    if (i in self.flow_timestamp) and (len(self.flow_timestamp[i]) == 1):
                        start_byte = self.flow_timestamp[i][0][0]
                        start_pkt = self.flow_timestamp[i][0][1]
                        start_time = self.flow_timestamp[i][0][2]
                        cur_byte = self.flow_stat_links[tmp][0][0]
                        cur_pkt = self.flow_stat_links[tmp][0][1]
                        cur_time = self.flow_stat_links[tmp][0][2]
                        self.flow_timestamp[i].pop(0)
                        throughput = ((cur_byte - start_byte) / (cur_time - start_time)) * 8
                        pktpersec = (cur_pkt - start_pkt) / (cur_time - start_time)

                    if throughput != -1:
                        filename = "Host_{0}.csv".format(i).replace(":", "-")
                        if not os.path.isfile(filename):
                            self._append_list_as_row(filename, ['Throughput', 'Pkt/sec'])
                        self._append_list_as_row(filename, [throughput, pktpersec])

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        msg = ev.msg
        port_stat_reply = msg.to_jsondict()
        port_stat = port_stat_reply['OFPPortStatsReply']['body'][0]['OFPPortStats']
        tx_p, tx_b = port_stat['tx_packets'], port_stat['tx_bytes']
        rx_p, rx_b = port_stat['rx_packets'], port_stat['rx_bytes']
        tx_d, rx_d = port_stat['tx_dropped'], port_stat['rx_dropped']
        tmp = "S{0}-P{1}".format(msg.datapath.id, port_stat['port_no'])
        self.port_stat_links[tmp].append([tx_p, rx_p, tx_b, rx_b, tx_d, rx_d])

        for dst_switch, values in self.adjacency[msg.datapath.id].items():
            if values == port_stat['port_no']:
                check_more_than_zero = True
                filename = self.csv_filename["[{0}, {1}]".format(msg.datapath.id, dst_switch)]
                if not os.path.isfile(filename):
                    self._append_list_as_row(filename, ['Timestamp', 'Tx_Packet', 'Rx_Packet', 'Dropped', 'BW_Utilization'])
                if len(self.port_stat_links[tmp]) == 1:
                    bw_util = (self.port_stat_links[tmp][0][2] + self.port_stat_links[tmp][0][3]) / 1310720
                    dropped = self.port_stat_links[tmp][0][4] + self.port_stat_links[tmp][0][5]
                    row_contents = [time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), self.port_stat_links[tmp][0][0], \
                        self.port_stat_links[tmp][0][1], dropped, bw_util * 1310720]
                    '''
                    random_val = (randint(3, 9) / 100)
                    if bw_util + random_val > 0.65 and ([msg.datapath.id, dst_switch] not in self.queue_for_re_routing[0]):
                        self.queue_for_re_routing[0].append([msg.datapath.id, dst_switch])
                        self.print_bw_util.append([msg.datapath.id, dst_switch, bw_util, bw_util + random_val])
                    '''
                    if bw_util < 1e-03:
                        check_more_than_zero = False

                elif len(self.port_stat_links[tmp]) == 2:
                    bw_util = ((self.port_stat_links[tmp][1][2] - self.port_stat_links[tmp][0][2]) + \
                                (self.port_stat_links[tmp][1][3] - self.port_stat_links[tmp][0][3])) / 1310720
                    dropped = (self.port_stat_links[tmp][1][4] - self.port_stat_links[tmp][0][4]) + \
                        (self.port_stat_links[tmp][1][5] - self.port_stat_links[tmp][0][5])
                    row_contents = [time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), self.port_stat_links[tmp][1][0] - self.port_stat_links[tmp][0][0], \
                        self.port_stat_links[tmp][1][1] - self.port_stat_links[tmp][0][1], dropped, bw_util * 1310720]
                    '''
                    random_val = (randint(3, 9) / 100)
                    if bw_util + random_val > 0.65 and ([msg.datapath.id, dst_switch] not in self.queue_for_re_routing[0]):
                        self.queue_for_re_routing[0].append([msg.datapath.id, dst_switch])
                        self.print_bw_util.append([msg.datapath.id, dst_switch, bw_util, bw_util + random_val])
                    '''
                    if bw_util < 1e-03:
                        check_more_than_zero = False

                if check_more_than_zero:
                    self._append_list_as_row(filename, row_contents)
                    '''
                    number = int(filename.split('./link')[1].split('.csv')[0])
                    if number not in self.data_for_train:
                        self.data_for_train[number] = []
                    self.data_for_train[number].append([row_contents[-1]])
                    '''
        
        print("Switch : {0} || Port : {1}".format(msg.datapath.id, port_stat['port_no']))
        if len(self.port_stat_links[tmp]) == 1:
            print("Tx : {0} packets | Rx:{1} packets".format(self.port_stat_links[tmp][0][0], self.port_stat_links[tmp][0][1]))
            print("BW Utilization (10 Mbps) : {0} %".format((self.port_stat_links[tmp][0][2] + \
                self.port_stat_links[tmp][0][3]) / 1310720 * 100))
        elif len(self.port_stat_links[tmp]) == 2:
            print("Tx : {0} packets | Rx:{1} packets".format(self.port_stat_links[tmp][1][0] - self.port_stat_links[tmp][0][0]\
                , self.port_stat_links[tmp][1][1]- self.port_stat_links[tmp][0][1]))
            print("BW Utilization (10 Mbps) : {0} %".format(((self.port_stat_links[tmp][1][2] - self.port_stat_links[tmp][0][2]) + \
                            (self.port_stat_links[tmp][1][3] - self.port_stat_links[tmp][0][3])) / 1310720 * 100))
        print("+" * 50)
        


        if len(self.port_stat_links[tmp]) == 2:
            self.port_stat_links[tmp].pop(0)
        

    def _append_list_as_row(self, file_name, list_of_elem):
        with open(file_name, 'a+', newline='') as write_obj:
            csv_writer = csv.writer(write_obj)
            csv_writer.writerow(list_of_elem)

    def get_paths(self, src, dst):
        '''
        Get all paths from src to dst using DFS algorithm    
        '''
        if src == dst:
            # host target is on the same switch
            return [[src]]
        paths = []
        stack = [(src, [src])]
        while stack:
            (node, path) = stack.pop()
            for next in set(self.adjacency[node].keys()) - set(path):
                if next is dst:
                    paths.append(path + [next])
                else:
                    stack.append((next, path + [next]))
        print("Available paths from ", src, " to ", dst, " : ", paths)
        return paths

    def get_link_cost(self, s1, s2):
        '''
        Get the link cost between two switches 
        '''
        e1 = self.adjacency[s1][s2]
        e2 = self.adjacency[s2][s1]
        bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
        ew = REFERENCE_BW/bl
        return ew

    def get_path_cost(self, path):
        '''
        Get the path cost
        '''
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(path[i], path[i+1])
        return cost

    def get_optimal_paths(self, src, dst):
        '''
        Get the n-most optimal paths according to MAX_PATHS
        '''
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        return sorted(paths, key=lambda x: self.get_path_cost(x))[0:(paths_count)]

    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
        Add the ports that connects the switches for all paths
        '''
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.adjacency[s1][s2]
                p[s1] = (in_port, out_port)
                in_port = self.adjacency[s2][s1]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
        return paths_p

    def generate_openflow_gid(self):
        '''
        Returns a random OpenFlow group id
        '''
        n = random.randint(0, 2**32)
        while n in self.group_ids:
            n = random.randint(0, 2**32)
        return n


    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst):
        computation_start = time.time()
        paths = self.get_optimal_paths(src, dst)
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
            print(path, "cost = ", pw[len(pw) - 1])
        sum_of_pw = sum(pw) * 1.0
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        switches_in_paths = set().union(*paths)

        for node in switches_in_paths:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            ports = defaultdict(list)
            actions = []
            i = 0

            for path in paths_with_ports:
                if node in path:
                    in_port = path[node][0]
                    out_port = path[node][1]
                    if (out_port, pw[i]) not in ports[in_port]:
                        ports[in_port].append((out_port, pw[i]))
                i += 1

            for in_port in ports:

                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )

                out_ports = ports[in_port]
                # print out_ports 

                if len(out_ports) > 1:
                    group_id = None
                    group_new = False

                    if (node, src, dst) not in self.multipath_group_ids:
                        group_new = True
                        self.multipath_group_ids[
                            node, src, dst] = self.generate_openflow_gid()
                    group_id = self.multipath_group_ids[node, src, dst]

                    buckets = []
                    # print "node at ",node," out ports : ",out_ports
                    for port, weight in out_ports:
                        bucket_weight = int(round((1 - weight/sum_of_pw) * 10))
                        bucket_action = [ofp_parser.OFPActionOutput(port)]
                        buckets.append(
                            ofp_parser.OFPBucket(
                                weight=bucket_weight,
                                watch_port=port,
                                watch_group=ofp.OFPG_ANY,
                                actions=bucket_action
                            )
                        )

                    if group_new:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_ADD, ofp.OFPGT_SELECT, group_id,
                            buckets
                        )
                        dp.send_msg(req)
                    else:
                        req = ofp_parser.OFPGroupMod(
                            dp, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT,
                            group_id, buckets)
                        dp.send_msg(req)

                    actions = [ofp_parser.OFPActionGroup(group_id)]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)

                elif len(out_ports) == 1:
                    actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                    self.add_flow(dp, 32768, match_ip, actions)
                    self.add_flow(dp, 1, match_arp, actions)
        print("Path installation finished in ", time.time() - computation_start) 
        return paths_with_ports[0][src][1]

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # print "Adding flow ", match, actions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        print("switch_features_handler is called")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.datapath_for_del.append(datapath)
        print("Switch : {0} Connected".format(datapath.id))

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for p in ev.msg.body:
            self.bandwidths[switch.id][p.port_no] = p.curr_speed

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
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
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return

        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)

        out_port = ofproto.OFPP_FLOOD

        if arp_pkt:
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            self.arp_table[src_ip] = src
            if arp_pkt.opcode == arp.ARP_REPLY:
                #self.arp_table[src_ip] = src
                if self._mac_learning(dpid, src, in_port):
                    self._arp_forwarding(msg, src_ip, dst_ip, eth)

                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
                
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    #self.arp_table[src_ip] = src
                    if self._mac_learning(dpid, src, in_port):
                        self._arp_forwarding(msg, src_ip, dst_ip, eth)
                        
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
                    self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse

                else:
                    if self._mac_learning(dpid, src, in_port):
                        self._arp_forwarding(msg, src_ip, dst_ip, eth)

        if ip_pkt:
            mac_to_port_table = self.mac_to_port.get(dpid)
            if mac_to_port_table:
                if eth.dst in mac_to_port_table:
                    out_port = mac_to_port_table[dst]
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                    self.add_flow(datapath, 1, match, actions)
                    self._send_packet_out(datapath, msg.buffer_id, in_port,
                                         out_port, msg.data)
                else:
                    if self._mac_learning(dpid, src, in_port):
                        self._flood(msg)

        '''
        # print pkt

        actions = [parser.OFPActionOutput(out_port)]

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
        '''

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
        
        print("Topology All Path :")
        for i in self.all_path:
            print(i, ":", self.all_path[i])

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

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.switches = sorted(self.switches)
            self.datapath_list[switch.id] = switch

            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        print(ev)
        switch = ev.switch.dp.id
        if switch in self.switches:
            self.switches.remove(switch)
            del self.datapath_list[switch]
            del self.adjacency[switch]

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no

    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        # Exception handling if switch already deleted
        try:
            del self.adjacency[s1.dpid][s2.dpid]
            del self.adjacency[s2.dpid][s1.dpid]
        except KeyError:
            pass

    def _arp_forwarding(self, msg, src_ip, dst_ip, eth_pkt):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        out_port = self.mac_to_port[datapath.id].get(eth_pkt.dst)
        if out_port is not None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.dst,
                                    eth_type=eth_pkt.ethertype)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 1, match, actions)
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

    @set_ev_cls(event.EventHostAdd, MAIN_DISPATCHER)
    def host_add_handler(self, ev):
        HOST = ev.host
        self.host_faucet[HOST.port.dpid].append(HOST.port.port_no)
