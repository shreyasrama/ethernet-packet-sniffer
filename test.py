from subprocess import call, check_output

f = open("results.txt", "w")

print "Tests beginning."

print "TEST - IPv4 TCP"
out = check_output(["./sniffer", "tests/ipv4tcp.pcap"])
f.write("TEST - IPv4 TCP\n")
f.write(out)
call(["./sniffer", "tests/ipv4tcp.pcap"])

print "TEST - IPv4 UDP"
out = check_output(["./sniffer", "tests/ipv4udp.pcap"])
f.write("TEST - IPv4 UDP\n")
f.write(out)
call(["./sniffer", "tests/ipv4udp.pcap"])

print "TEST - IPv4 ICMP"
out = check_output(["./sniffer", "tests/ipv4icmp.pcap"])
f.write("TEST - IPv4 ICMP\n")
f.write(out)
call(["./sniffer", "tests/ipv4icmp.pcap"])

print "TEST - IPv6 EXTENSION HEADERS"
out = check_output(["./sniffer", "tests/ipv6exth.pcap"])
f.write("TEST - IPv6 EXTENSION HEADERS\n")
f.write(out)
call(["./sniffer", "tests/ipv6exth.pcap"])

print "TEST - IPv6 TCP"
out = check_output(["./sniffer", "tests/ipv6tcp.pcap"])
f.write("TEST - IPv6 TCP\n")
f.write(out)
call(["./sniffer", "tests/ipv6tcp.pcap"])

print "TEST - IPv6 UDP"
out = check_output(["./sniffer", "tests/ipv6udp.pcap"])
f.write("TEST - IPv6 UDP\n")
f.write(out)
call(["./sniffer", "tests/ipv6udp.pcap"])

print "TEST - IPv6 ICMPv6"
out = check_output(["./sniffer", "tests/ipv6icmpv6.pcap"])
f.write("TEST - IPv6 ICMPv6\n")
f.write(out)
call(["./sniffer", "tests/ipv6icmpv6.pcap"])

print "Tests complete. Results written to results.txt."

f.close()