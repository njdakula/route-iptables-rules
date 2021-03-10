#!/bin/bash
v2ray --config=/etc/v2ray/config.json &
wan_ip=`ifconfig ppp0 | grep "inet" | awk '{print $2}'`
ip rule add fwmark 1 table 100
ip route add local 0.0.0.0/0 dev lo table 100
wget -P . http://www.ipdeny.com/ipblocks/data/countries/cn.zone
ipset -N chniproute hash:net maxelem 65536
for ip in $(cat '/home/dakula/bin/cn.zone'); do
  ipset add chniproute $ip
done
rm /home/dakula/bin/cn.zone

#nat table creat chains 
iptables -t nat -N delegate_postrouting 
iptables -t nat -N delegate_prerouting 
iptables -t nat -N zone_lan_postrouting 
iptables -t nat -N zone_lan_prerouting 
iptables -t nat -N zone_wan_postrouting 
iptables -t nat -N zone_wan_prerouting 

#add nat table rules
iptables -t nat -A POSTROUTING -j delegate_postrouting
iptables -t nat -A PREROUTING -j delegate_prerouting

iptables -t nat -A delegate_postrouting -o enp6s0 -j zone_lan_postrouting
iptables -t nat -A delegate_postrouting -o ppp0 -j zone_wan_postrouting
iptables -t nat -A delegate_postrouting -o enp7s0 -j zone_wan_postrouting
iptables -t nat -A delegate_prerouting -i enp6s0 -j zone_lan_prerouting
iptables -t nat -A delegate_prerouting -i ppp0 -j zone_wan_prerouting
iptables -t nat -A delegate_prerouting -i enp7s0 -j zone_wan_prerouting

iptables -t nat -A zone_lan_postrouting -s 192.168.100.0/24 -d 192.168.1.21/24 -p tcp -m tcp --dport 6800 -j SNAT --to-source 192.168.100.1
iptables -t nat -A zone_lan_postrouting -s 192.168.100.0/24 -d 192.168.1.21/24 -p udp -m udp --dport 6800 -j SNAT --to-source 192.168.100.1

iptables -t nat -A zone_lan_prerouting -s 192.168.100.0/24 -d $wan_ip/32 -p tcp -m tcp --dport 22500 -j DNAT --to-destination 192.168.100.21:6800
iptables -t nat -A zone_lan_prerouting -s 192.168.100.0/24 -d $wan_ip/32 -p udp -m udp --dport 22500 -j DNAT --to-destination 192.168.100.21:6800

iptables -t nat -A zone_wan_postrouting -j MASQUERADE
iptables -t nat -A zone_wan_prerouting -p tcp -m tcp --dport 22500 -j DNAT --to-destination 192.168.100.21:6800
iptables -t nat -A zone_wan_prerouting -p udp -m udp --dport 22500 -j DNAT --to-destination 192.168.100.21:6800
iptables -t nat -A zone_wan_prerouting -p tcp -m tcp --dport 22500 -j REDIRECT --to-ports 22 
iptables -t nat -A zone_wan_prerouting -p udp -m udp --dport 22500 -j REDIRECT --to-ports 22

#mangle table creat chains 
iptables -t mangle -N mangle_postrouting 
iptables -t mangle -N mangle_prerouting 
iptables -t mangle -N mangle_output 
iptables -t mangle -N mangle_lan_postrouting 
iptables -t mangle -N mangle_lan_prerouting 
iptables -t mangle -N mangle_lan_output 
iptables -t mangle -N mangle_wan_postrouting 
iptables -t mangle -N mangle_wan_prerouting 
iptables -t mangle -N mangle_wan_output 
iptables -t mangle -N V2RAY_MASK 
iptables -t mangle -N V2RAY 

#add mangle table rules
iptables -t mangle -A POSTROUTING -j mangle_postrouting
iptables -t mangle -A PREROUTING -j mangle_prerouting
iptables -t mangle -A OUTPUT -j mangle_output

iptables -t mangle -A mangle_postrouting -o enp6s0 -j mangle_lan_postrouting
iptables -t mangle -A mangle_postrouting -o ppp0 -j mangle_wan_postrouting
iptables -t mangle -A mangle_postrouting -o enp7s0 -j mangle_wan_postrouting
iptables -t mangle -A mangle_prerouting -i enp6s0 -j mangle_lan_prerouting
iptables -t mangle -A mangle_prerouting -i ppp0 -j mangle_wan_prerouting
iptables -t mangle -A mangle_prerouting -i enp7s0 -j mangle_wan_prerouting
iptables -t mangle -A mangle_output -o enp6s0 -j mangle_lan_output
iptables -t mangle -A mangle_output -o ppp0 -j mangle_wan_output
iptables -t mangle -A mangle_output -o enp7s0 -j mangle_wan_output

iptables -t mangle -A mangle_lan_prerouting -j V2RAY
iptables -t mangle -A mangle_wan_output -j V2RAY_MASK

#add mangle table V2RAY_MASK chain rules(local tproxy)
iptables -t mangle -A V2RAY_MASK -m set --match-set chniproute dst -j RETURN
#iptables -t mangle -A V2RAY_MASK -p udp -m udp ! --dport 53 -m set --match-set chniproute dst -j RETURN
#iptables -t mangle -A V2RAY_MASK -p tcp -m set --match-set chniproute dst -j RETURN
iptables -t mangle -A V2RAY_MASK -d 127.0.0.0/24 -j RETURN
#iptables -t mangle -A V2RAY_MASK -d 224.0.0.0/4 -j RETURN
#iptables -t mangle -A V2RAY_MASK -d 255.255.255.255/32 -j RETURN
#iptables -t mangle -A V2RAY_MASK -p udp -m udp --sport 8964 -j RETURN
#iptables -t mangle -A V2RAY_MASK -p tcp -m tcp --sport 8964 -j RETURN
#iptables -t mangle -A V2RAY_MASK -p tcp -m tcp --sport 22 -j RETURN
#iptables -t mangle -A V2RAY_MASK -p udp -m udp --sport 22 -j RETURN
#iptables -t mangle -A V2RAY_MASK -p udp -m udp --sport 53 -j RETURN
iptables -t mangle -A V2RAY_MASK -d 192.168.0.0/16 -j RETURN
#iptables -t mangle -A V2RAY_MASK -d 192.168.0.0/16 -p udp ! --dport 53 -j RETURN
iptables -t mangle -A V2RAY_MASK -d 172.16.0.0/16 -j RETURN
#iptables -t mangle -A V2RAY_MASK -s 192.168.1.21/32 -p udp -m udp --dport 53 -j RETURN
iptables -t mangle -A V2RAY_MASK -m mark --mark 0x100 -j RETURN
#iptables -t mangle -A V2RAY_MASK -p udp -m udp --dport 53 -j MARK --set-xmark 0x1/0xffffffff
#iptables -t mangle -A V2RAY_MASK -s 192.168.1.21/32 -p udp -m udp --dport 53 -j MARK --set-xmark 0x1/0xffffffff
iptables -t mangle -A V2RAY_MASK -p udp -j MARK --set-mark 1
iptables -t mangle -A V2RAY_MASK -p tcp -j MARK --set-mark 1

#add chain V2RAY rules(prerouting tproxy)
iptables -t mangle -A V2RAY -m set --match-set chniproute dst -j RETURN
iptables -t mangle -A V2RAY -d 192.168.0.0/16 -p tcp -j RETURN
iptables -t mangle -A V2RAY -d 192.168.0.0/16 -p udp ! --dport 53 -j RETURN
iptables -t mangle -A V2RAY -d 127.0.0.0/24 -j RETURN
iptables -t mangle -A V2RAY -d 172.16.0.0/16 -j RETURN
iptables -t mangle -A V2RAY -d 224.0.0.0/4 -j RETURN
iptables -t mangle -A V2RAY -d 255.255.255.255/32 -j RETURN
iptables -t mangle -A V2RAY -p udp -j TPROXY --on-port 1889 --on-ip 192.168.100.1 --tproxy-mark 1
iptables -t mangle -A V2RAY -p tcp -j TPROXY --on-port 1889 --on-ip 192.168.100.1 --tproxy-mark 1

#filter table creat chain
iptables -N delegate_forward
iptables -N delegate_input
iptables -N delegate_output

iptables -N forwarding_lan_rule
iptables -N forwarding_wan_rule
iptables -N input_lan_rule
iptables -N input_wan_rule
iptables -N output_lan_rule
iptables -N output_wan_rule
iptables -N reject
iptables -N syn_flood
iptables -N zone_lan_dest_ACCEPT
iptables -N zone_lan_forward
iptables -N zone_lan_input
iptables -N zone_lan_output
iptables -N zone_lan_src_ACCEPT
iptables -N zone_wan_dest_ACCEPT
iptables -N zone_wan_dest_REJECT
iptables -N zone_wan_forward
iptables -N zone_wan_input
iptables -N zone_wan_output
iptables -N zone_wan_src_REJECT

#add filter table rules
iptables -P FORWARD DROP
iptables -A INPUT -j delegate_input
iptables -A FORWARD -j delegate_forward
iptables -A OUTPUT -j delegate_output

iptables -A delegate_forward -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A delegate_forward -i enp6s0 -j zone_lan_forward
iptables -A delegate_forward -i enp7s0 -j zone_wan_forward
iptables -A delegate_forward -i ppp0 -j zone_wan_forward
iptables -A delegate_forward -j reject
iptables -A delegate_input -i lo -j ACCEPT
iptables -A delegate_input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A delegate_input -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j syn_flood 
iptables -A delegate_input -i enp6s0 -j zone_lan_input 
iptables -A delegate_input -i ppp0 -j zone_wan_input 
iptables -A delegate_input -i enp7s0 -j zone_wan_input 
iptables -A delegate_output -o lo -j ACCEPT
iptables -A delegate_output -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A delegate_output -o enp6s0 -j  zone_lan_output
iptables -A delegate_output -o ppp0 -j  zone_wan_output
iptables -A delegate_output -o enp7s0 -j  zone_wan_output
iptables -A reject -p tcp -j REJECT --reject-with tcp-reset
iptables -A reject -j REJECT --reject-with icmp-port-unreachable
iptables -A syn_flood -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m limit --limit 25/sec --limit-burst 50 -j RETURN
iptables -A syn_flood -j REJECT
iptables -A zone_lan_dest_ACCEPT -o enp6s0 -j ACCEPT
iptables -A zone_lan_forward -m comment --comment "forwarding lan -> wan" -j zone_wan_dest_ACCEPT
iptables -A zone_lan_forward -m conntrack --ctstate DNAT -m comment --comment "Accept port forwards" -j ACCEPT
iptables -A zone_lan_forward -j zone_lan_dest_ACCEPT
iptables -A zone_lan_input -m comment --comment "user chain for input" -j input_lan_rule
iptables -A zone_lan_input -m conntrack --ctstate DNAT -m comment --comment "Accept port redirections" -j ACCEPT
iptables -A zone_lan_input -j zone_lan_src_ACCEPT
iptables -A zone_lan_output -j zone_lan_dest_ACCEPT
iptables -A zone_lan_src_ACCEPT -i enp6s0 -j ACCEPT
iptables -A zone_wan_dest_ACCEPT -o ppp0 -j ACCEPT
iptables -A zone_wan_dest_ACCEPT -o enp7s0 -j ACCEPT
iptables -A zone_wan_dest_REJECT -o ppp0 -j reject
iptables -A zone_wan_dest_REJECT -o enp7s0 -j reject
iptables -A zone_wan_forward -m conntrack --ctstate DNAT -m comment --comment "Accept port forwards" -j ACCEPT
iptables -A zone_wan_forward -j zone_wan_dest_REJECT
iptables -A zone_wan_input -p udp -m udp --dport 68 -m comment --comment Allow-DHCP-Renew -j ACCEPT
iptables -A zone_wan_input -p icmp -m icmp --icmp-type 8 -m comment --comment Allow-Ping -j ACCEPT
iptables -A zone_wan_input -m conntrack --ctstate DNAT -m comment --comment "Accept port redirections" -j ACCEPT
iptables -A zone_wan_input -j zone_wan_src_REJECT
iptables -A zone_wan_output -m comment --comment "user chain for output" -j output_wan_rule
iptables -A zone_wan_output -j zone_wan_dest_ACCEPT
iptables -A zone_wan_src_REJECT -i ppp0 -j reject
iptables -A zone_wan_src_REJECT -i enp7s0 -j reject
