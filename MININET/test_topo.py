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
        number_switch = 2
        for i in ['s'+str(i+1) for i in range(number_switch)]:
            Switch.append(self.addSwitch(i))	

        #Add Links
        info('*** Creating Links (Host -- Switch)\n')
        """
        self.addLink(S1,S2)
        self.addLink(S2,S3)
        self.addLink(S1,H1)
        self.addLink(S2,H2)
        self.addLink(S3,H3)
        """
        for i in range(number_switch):
            self.addLink(Switch[i], Host[i])
	#Add Host3 to S1
	self.addLink(Switch[1], Host[2])

        
        info('*** Creating Links (Switch -- Switch)\n')
        """
        self.addLink(Switch[0], Switch[4])
        self.addLink(Switch[1], Switch[4])
        self.addLink(Switch[2], Switch[4])
        self.addLink(Switch[3], Switch[4])
	"""
	self.addLink(Switch[0],Switch[1])
        

topos = { 'mytopo': ( lambda: MyTopo() ) }
