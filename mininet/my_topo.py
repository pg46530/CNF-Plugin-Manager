#!/usr/bin/env python3
# SPDX-License-Identifier: ANCL-1.0
# Copyright (c) 2026  jfpereira <d12267@di.uminho.pt> — di.uminho.pt
# Academic use only · no commercial use · see LICENSE
# AI-assisted development: Claude (Anthropic)

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink

from p4_mininet import P4Host
from p4runtime_switch import P4RuntimeSwitch

import argparse
from time import sleep

def host_mac(net, n):
    return f"aa:00:00:00:{net:02x}:{n:02x}"

def host_ip(net, dev, mask):
    return f"10.0.{net}.{dev}/{mask}"

def device_mac(id, port):
    return f"cc:00:00:00:{id:02x}:{port:02x}"


class MyTopo(Topo):
    def __init__(self, 
                sw_path,
                thrift_port,
                grpc_port,
                **opts):

        # Initialize topology and default options
        super().__init__(**opts)

        # ------------------- creating devices ------------------------
        d1 = self.addSwitch("d1", sw_path=sw_path, thrift_port=thrift_port, grpc_port = grpc_port, device_id = 1, cpu_port = 510)
        d2 = self.addSwitch("d2", sw_path=sw_path, thrift_port=thrift_port+1, grpc_port = grpc_port+1, device_id = 2, cpu_port = 510)
        d3 = self.addSwitch("d3", sw_path=sw_path, thrift_port=thrift_port+2, grpc_port = grpc_port+2, device_id = 3, cpu_port = 510)

        # -------------------- creating hosts -------------------------
        h1 = self.addHost("h1", ip=host_ip(1, 1, 24), mac=host_mac(1,1))
        h2 = self.addHost("h2", ip=host_ip(1, 2, 24), mac=host_mac(1,2))
        h3 = self.addHost("h3", ip=host_ip(1, 3, 24), mac=host_mac(1,3))
        h4 = self.addHost("h4", mac=host_mac(2,4))
        h5 = self.addHost("h5", mac=host_mac(2,5))
        h6 = self.addHost("h6", mac=host_mac(2,6))

        # -------------------- creating links -------------------------
        # --------------------- hosts to l2 switch -------------------
        self.addLink(h1, d1, port2=1, addr2=device_mac(1,1))
        self.addLink(h2, d1, port2=2, addr2=device_mac(1,2))
        self.addLink(h3, d1, port2=3, addr2=device_mac(1,3))

        self.addLink(h4, d3, port2=1, addr2=device_mac(3,1))
        self.addLink(h5, d3, port2=2, addr2=device_mac(3,2))
        self.addLink(h6, d3, port2=3, addr2=device_mac(3,3))

        # --------------------- l2-switch to l3-switch to l2-switch ------------
        self.addLink(d1, d2, port1=4, port2=1, addr1=device_mac(1,4), addr2=device_mac(2,1), delay='10ms', loss=1)
        self.addLink(d3, d2, port1=4, port2=2, addr1=device_mac(3,4), addr2=device_mac(2,2), delay='10ms', loss=1)

def main():
    parser = argparse.ArgumentParser(description='Mininet demo')
    parser.add_argument('--behavioral-exe', help='Path to behavioral executable',
                        type=str, action="store", default='simple_switch_grpc')
    parser.add_argument('--thrift-port', help='Thrift server port for table updates',
                        type=int, action="store", default=9090)
    parser.add_argument('--grpc-port', help='gRPC server port for controller comm',
                        type=int, action="store", default=50051)
    args = parser.parse_args()



    topo = MyTopo(args.behavioral_exe,
                   args.thrift_port,
                   args.grpc_port)

    # the host class is the P4Host
    # the switch class is the P4RuntimeSwitch
    net = Mininet(topo = topo,
                  host = P4Host,
                  switch = P4RuntimeSwitch,
                  controller = None,
                  link=TCLink)

    net.start()

    sleep(1)  # time for the host and switch confs to take effect

    # --------- host config in network 1 ---------
    GW_IP = "10.0.1.254"

    host = net.get("h1")
    host.cmd(f"ip route replace default via {GW_IP}")

    host = net.get("h2")
    host.cmd(f"ip route replace default via {GW_IP}")

    host = net.get("h3")
    host.cmd(f"ip route replace default via {GW_IP}")

    # --------- host config in network 2 ---------
    for h in ["h4", "h5", "h6"]:
        host = net.get(h)
        host.cmd('mount --bind /dev/null /etc/dhcp/dhclient-exit-hooks.d/resolved')
        host.cmd(f"rm -f mininet/run-time/dhclient-{h}.leases")
        host.cmd(f"touch mininet/run-time/dhclient-{h}.leases")
        host.cmd("ip addr flush dev eth0")
        host.cmd(f"dhclient -lf mininet/run-time/dhclient-{h}.leases eth0 &")

  
    print("Ready !")


    CLI( net )
    net.stop()

if __name__ == '__main__':
    setLogLevel( 'info' )
    main()
