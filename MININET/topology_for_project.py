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
        number_host = 6
        #bw_fast_eth = 100
        for i in ['h'+str(i+1) for i in range(number_host)]:
            Host.append(self.addHost(i))

        #Add switchs
        info('*** Adding Switches\n')
        Switch = []
        number_switch = 6
        for i in ['s'+str(i+1) for i in range(number_switch)]:
            Switch.append(self.addSwitch(i))	

        #Add Links
        info('*** Creating Links (Host -- Switch)\n')
        for i in range(number_switch):
            self.addLink(Switch[i], Host[i], bw = 100)

        
        info('*** Creating Links (Switch -- Switch)\n')
        #Circle 1
        for i in range(int(number_switch // 2)):
            self.addLink(Switch[i], Switch[(i + 1) % 3], bw = 100)

        #Circle 2
        for i in range(int(number_switch // 2)):
            self.addLink(Switch[i + 3], Switch[((i + 1) % 3) + 3], bw = 100)

        #Link between Circle 1 & Circle 2
        self.addLink(Switch[2], Switch[5], bw = 100)
        self.addLink(Switch[1], Switch[4], bw = 100)
        

topos = { 'mytopo': ( lambda: MyTopo() ) }
