from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu import cfg
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu.lib.packet import icmp
#This file acts as an openflow load balancer on a network using the ryu framework
#Listens for arp requests and instructs requesting servers to modify their arp table to backend servers in round robin fashion
#Listens for ping requests after arp requests and sets up an openflow protocol for the requesting host and the backend server
#The number of servers/ virtual IP can be modified in the configuration.conf file otherwise the default virtual IP is 10.0.0.15
#the default number of servers will be 8 with 6 front end and 2 back end

class Controller(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)
        self.packetNum = 0
        self.nextBackEnd = 0
        CONF = cfg.CONF
        self.mac_to_port = {}
        # read the values from the config file and construct the action array
        CONF.register_opts([
            cfg.IntOpt('front_end_testers', default=6, help=('front end')),
            cfg.IntOpt('back_end_servers', default=2, help=('back end')),
            cfg.StrOpt('virtual_ip', default='10.0.0.15', help=('virt-ip'))])
        self.numBackEnds = CONF.back_end_servers
        self.numFrontEnds = CONF.front_end_testers
        self.virtIP = CONF.virtual_ip
        self.numServers = self.numBackEnds + self.numFrontEnds
        self.servers = []
        self.portMatches = {}
        #add each servers ip and mac to an array
        for i in range(1,self.numServers+1):
            ip_addr = '10.0.0.{}'.format(str(i))
            mac_addr = '00:00:00:00:00:{:02x}'.format(i)
            self.servers.append((ip_addr,mac_addr))


    #helper method to add openflow rules for the swtich
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    #handles any incoming packet
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):

        self.packetNum = self.packetNum + 1
        #extract the usefull information
        dstIP = ''
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        ofp_parser = dp.ofproto_parser
        # check the protocols for the incomming packet
        pkt = packet.Packet(ev.msg.data)
        pkt_arp = pkt.get_protocol(arp.arp)
        pkt_Ipv4 = pkt.get_protocol(ipv4.ipv4)
        pkt_Ipv6 = pkt.get_protocol(ipv6.ipv6)
        pkt_ethernet = pkt.get_protocol(ethernet.ethernet)
        pkt_icmp = pkt.get_protocol(icmp.icmp)
        in_port = msg.match['in_port']
        # if applicable print usefull information about the incoming packets
        if (pkt_arp):
            print'Packet:', self.packetNum, 'received on port:', in_port, 'ETH ARP'
            print '\tARP'
            print '\t\tDest IP', pkt_arp.dst_ip
            print '\t\tSRC IP', pkt_arp.src_ip
            print '\t\tFrom MAC', pkt_arp.src_mac
            print '\t\tTo MAC', pkt_arp.dst_mac
            dstIP = pkt_arp.dst_ip

        if (pkt_icmp):
            print 'Packet:', self.packetNum, 'received on port:', in_port, 'ETH PING'
            print '\tPING'
        if (pkt_Ipv4):
            print '\tIPV4'
            print '\t\tCheck sum:', pkt_Ipv4.csum
            print '\t\tFrom IP:  ', pkt_Ipv4.src
            print '\t\tTo IP:    ', pkt_Ipv4.dst
            print '\t\tLength    ', pkt_Ipv4.total_length
        else:
            print '\tNOT IPV4'

        if (pkt_Ipv6):
            print '\tIPV6'
        else:
            print '\tNOT IPV6'

        if (pkt_ethernet):
            print '\tETH'
            print '\t\tFrom MAC:', pkt_ethernet.src
            print '\t\tTo MAC:  ', pkt_ethernet.dst
        print '\tController Switch (OF)'
        print '\t\t', msg.datapath.address
        print '\n'

        #If the packet is an arp packet modify the requesting hosts arp tables
        if (pkt_arp):
            #if the request is coming from one of the front end servers
            if (pkt_arp.dst_ip == self.virtIP):

                actions = [ofp_parser.OFPActionOutput(in_port)]
                dual_packet = self.handle_front_end_arp(pkt_arp,in_port)
                out = ofp_parser.OFPPacketOut(
                    datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER,
                    actions=actions, data=dual_packet.data)
                #send the message back to the switch
                dp.send_msg(out)

            #otherwise the request is coming from a backend server to the cooresponding frontend server
            else:
                dual_packet = self.handle_back_end_arp(pkt_arp,in_port)
                actions = [ofp_parser.OFPActionOutput(in_port)]
                out = ofp_parser.OFPPacketOut(
                datapath=dp, buffer_id=ofp.OFP_NO_BUFFER, in_port=ofp.OFPP_CONTROLLER,
                actions=actions, data=dual_packet.data)
                dp.send_msg(out)

        #IF packet is icmp construct flows from backend server to front end and vice versa
        elif pkt_icmp:
            #get the matched out_port for the match/actions
            self.set_up_flows(in_port,ofp_parser,dp)
        else:
            print 'NOT IMPLEMENTED'

    #construct ethernet and arp packets to return to the requesting fronend host
    def handle_front_end_arp(self, pkt_arp, in_port):
        srcMac = '' + pkt_arp.src_mac
        srcIP = '' + pkt_arp.src_ip
        dstIP = '' + pkt_arp.dst_ip
        dstMac = '' + pkt_arp.dst_mac

        print
        'ARP REQUEST TO VIRTUAL IP ', srcIP, 'to ', dstIP

        # choose the next backend server to add to the senders arp table
        nextServer = (self.nextBackEnd % self.numBackEnds) + self.numFrontEnds
        self.nextBackEnd = self.nextBackEnd + 1
        # match the two server numbers together(for constructing flows)
        self.portMatches[in_port] = nextServer + 1
        self.portMatches[nextServer + 1] = in_port
        backServer = self.servers[nextServer]
        print
        'next back server', backServer

        # construct the packets
        eth_packet = ethernet.ethernet(dst=srcMac, src=backServer[1], ethertype=ether.ETH_TYPE_ARP)
        arp_packet = arp.arp(opcode=arp.ARP_REPLY, src_mac=backServer[1], src_ip=self.virtIP, dst_mac=srcMac,
                             dst_ip=srcIP, hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4)

        dual_packet = packet.Packet()
        dual_packet.add_protocol(eth_packet)
        dual_packet.add_protocol(arp_packet)
        dual_packet.serialize()
        return dual_packet

    #construct the ethernet and arp packets to return to the requesting back-end server
    def handle_back_end_arp(self,pkt_arp, in_port):
        dstMac = '' + pkt_arp.dst_mac
        dstIP = '' + pkt_arp.dst_ip

        srcIP = '' + pkt_arp.src_ip
        srcMac = '' + pkt_arp.src_mac

        senderNum = int(srcIP.replace('10.0.0.', ''))
        receieverNum = self.portMatches[in_port]

        print
        'ARP REQUEST FROM BACKEND ,', srcIP, 'to ', dstIP, 'recv NUM', receieverNum, 'AND DSTMAC', \
        self.servers[receieverNum - 1][1]
        # construct the arp/ethernet reply packet to send to the backend server

        eth_packet = ethernet.ethernet(dst=srcMac, src=self.servers[receieverNum - 1][1], ethertype=ether.ETH_TYPE_ARP)
        arp_packet = arp.arp(opcode=arp.ARP_REPLY, src_mac=self.servers[receieverNum - 1][1],
                             src_ip=self.servers[receieverNum - 1][0], dst_mac=srcMac,
                             dst_ip=srcIP, hwtype=1, proto=ether.ETH_TYPE_IP, hlen=6, plen=4)

        dual_packet = packet.Packet()
        dual_packet.add_protocol(eth_packet)
        dual_packet.add_protocol(arp_packet)
        dual_packet.serialize()
        return dual_packet

    #set up the flows for the frontend and cooresponding backend server
    def set_up_flows(self, in_port, ofp_parser, dp):
        out_port = self.portMatches[in_port]
        print
        'PING MESSAGE FROM PORT ', in_port, 'GOING OUT PORT ', out_port
        print
        'THE IPV4 add at ', out_port, 'is', self.servers[out_port - 1][0]

        # set up flow for front_end -> to backend
        match = ofp_parser.OFPMatch(in_port=in_port, ipv4_dst=self.virtIP, eth_type=ether.ETH_TYPE_IP)
        actions = [ofp_parser.OFPActionSetField(ipv4_dst=self.servers[out_port - 1][0]),
                   ofp_parser.OFPActionOutput(out_port)]
        self.add_flow(dp, 1, match, actions)

        # set up flow for back_end -> to front_end
        match = ofp_parser.OFPMatch(in_port=out_port, ipv4_src=self.servers[out_port - 1][0],
                                    ipv4_dst=self.servers[in_port - 1][0], eth_type=ether.ETH_TYPE_IP)
        actions = [ofp_parser.OFPActionSetField(ipv4_src=self.virtIP), ofp_parser.OFPActionOutput(in_port)]
        self.add_flow(dp, 1, match, actions)
