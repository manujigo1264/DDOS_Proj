# Clear all rules in the nat table
iptables --table nat --flush

# Allow incoming TCP traffic from the gateway IP address to the same IP address with a rate limit of 25 requests per minute and a burst of 100
iptables -t nat -A PREROUTING -p tcp -s <gateway-ip> -d <gateway-ip> --syn -m limit --limit 25/m --limit-burst 100 -j ACCEPT

# Perform destination NAT for all incoming TCP traffic from the gateway IP address to 192.168.90.102
iptables -t nat -A PREROUTING -p tcp -s <gateway-ip> -d 192.168.90.102 --syn -j DNAT --to-destination 192.168.90.102

# Set a default policy of DROP for all incoming traffic in the nat table
iptables -t nat -P PREROUTING DROP

# Allow incoming TCP traffic with a destination IP address of 192.168.70.102 with a rate limit of 25 requests per minute and a burst of 100
iptables -t nat -A PREROUTING -p tcp -d 192.168.70.102 --syn -m limit --limit 25/m --limit-burst 100 -j ACCEPT

# Perform destination NAT for all incoming TCP traffic with a destination IP address of 192.168.70.102 to 192.168.70.200
iptables -t nat -A PREROUTING -p tcp -d 192.168.70.102 --syn -j DNAT --to-destination 192.168.70.200

# Set a default policy of DROP for all incoming traffic in the nat table
iptables -t nat -P PREROUTING DROP
