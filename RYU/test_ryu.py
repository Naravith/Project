from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet


class ExampleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ExampleSwitch13, self).__init__(*args, **kwargs)
        # initialize mac address table.
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        print("-" * 30)
        print("Swtich Features " * 3)
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        print("datapath.id {0} : {1}".format(type(datapath.id), datapath.id))
        print(datapath.__dict__)

        # install the table-miss flow entry.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        print("-" * 30)

    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # construct flow_mod message and send it.
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        print("ev {1} : {0}".format(ev.__dict__, type(ev.__dict__)))
        print("-" * 20, "ev" * 5, "-" * 20)
        msg = ev.msg
        print("msg {1} : {0}".format(msg.data, type(msg.data)))
        print("-" * 20, "msg" * 3, "-" * 20)
        datapath = msg.datapath
        print("datapath {1} : {0}".format(datapath.__dict__, type(datapath.__dict__)))
        print("-" * 20, "datapath", "-" * 20)
        ofproto = datapath.ofproto
        print("ofproto {1} : {0}".format(ofproto, type(ofproto)))
        print("-" * 20, "ofproto", "-" * 20)
        parser = datapath.ofproto_parser
        print("parser {1} : {0}".format(parser, type(parser)))
        print("-" * 20, "parser", "-" * 20)

        # get Datapath ID to identify OpenFlow switches.
        dpid = datapath.id
        print("dpid {1} : {0}".format(dpid, type(dpid)))
        print("-" * 20, "dpid" * 2, "-" * 20)
        self.mac_to_port.setdefault(dpid, {})
        print("MAC Table : {0}".format(self.mac_to_port))
        print("-" * 20, "Mac Table", "-" * 20)

        # analyse the received packets using the packet library.
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        dst = eth_pkt.dst
        src = eth_pkt.src
        print("pkt {1} : {0}".format(pkt, type(pkt)))
        print("-" * 20, "pkt" * 3, "-" * 20)
        # get the received port number from packet_in message.
        in_port = msg.match['in_port']
        print("msg.match {1} : {0}".format(msg.match, type(msg.match)))
        print("-" * 20, "msg.match", "-" * 20)

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        # Flow Table Easy Understanding
        print("Flow Tables:")
        for i in self.mac_to_port.keys():
            print("Switch : S{0}".format(i))
            for j in self.mac_to_port[i]:
                print("in-port: {0}   |   Mac: {1}".format(self.mac_to_port[i][j], j))

        print('-'*25)
        # if the destination mac address is already learned,
        # decide which port to output the packet, otherwise FLOOD.
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        # construct action list.
        actions = [parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time.
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        # construct packet_out message and send it.
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=in_port, actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)
