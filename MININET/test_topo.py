import pdb
from mininet.topo import Topo
from mininet.log import info

class MyTopo( Topo ):
    def __init__(self):
        "Create custom topo"
        # init Topology
        Topo.__init__(self)

        #Add hosts 
        info('*** Adding Hosts\n')
        Host = []
        number_host = 3
        bw_fast_eth = 100
        for i in ['h'+str(i+1) for i in range(number_host)]:
            Host.append(self.addHost(i))
        """
        H1 = self.addHost('h1')
        H2 = self.addHost('h2')
        H3 = self.addHost('h3')
        """

        #Add switchs
        info('*** Adding Switches\n')
        """
        S1 = self.addSwitch('s1')
        S2 = self.addSwitch('s2')
        S3 = self.addSwitch('s3')
        """
        Switch = []
        number_switch = 3
        for i in ['s'+str(i+1) for i in range(number_switch)]:
            Switch.append(self.addSwitch(i))	

        #Add Links
        info('*** Creating Links (Host -- Switch)\n')
        """
        self.addLink(S1,S2, bw = bw_fast_eth)
        self.addLink(S2,S3, bw = bw_fast_eth)
        self.addLink(S1,H1, bw = bw_fast_eth)
        self.addLink(S2,H2, bw = bw_fast_eth)
        self.addLink(S3,H3, bw = bw_fast_eth)
        """
        for i in range(number_switch):
            self.addLink(Switch[i], Host[i], bw = bw_fast_eth)
	    #Add Host3 to S1
	    #self.addLink(Switch[1], Host[2], bw = bw_fast_eth)

        
        info('*** Creating Links (Switch -- Switch)\n')
        """
        self.addLink(Switch[0], Switch[4], bw = bw_fast_eth)
        self.addLink(Switch[1], Switch[4], bw = bw_fast_eth)
        self.addLink(Switch[2], Switch[4], bw = bw_fast_eth)
        self.addLink(Switch[3], Switch[4], bw = bw_fast_eth)
	    """
        for i in range(1, number_switch):
            self.addLink(Switch[i - 1], Switch[i], bw = bw_fast_eth)
	    #self.addLink(Switch[0],Switch[1], bw = bw_fast_eth)
        

topos = { 'mytopo': ( lambda: MyTopo() ) }
