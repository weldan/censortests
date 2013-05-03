"""
censortests/testfilter.py 
http://sinarproject.org/
"""

"""
Credits to https://forum.lowyat.net/index.php?showtopic=2794929&view=findpost&p=60057869
"""
import time,argparse,os,re
from socket import socket, IPPROTO_TCP, TCP_NODELAY, timeout, gethostbyname, \
    getprotobyname, AF_INET, SOL_IP, SOCK_RAW, SOCK_DGRAM, IP_TTL, gethostbyaddr, error

class target:
    pass

class test:
    def test1(self, host, path="/"):
        print "## Test 1: Check DNS, and IP block: Testing Same IP, different Virtual Host"
        s = socket()
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.connect((host, 80))
        path_str = "GET %s HTTP/1.1\r\n\r\n" % path
        s.send(path_str)
        try:
            print s.recv(4096)
        except timeout:
            print "Timeout -- waited 5 seconds\n"   
            
    def test2(self, host, path="/"):
        print "## Test 2: Emulating a real web browser: Testing Same IP, actual Virtual Host, single packet"
        s = socket()
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.connect((host, 80))
        path_str = "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n" % (path, host)
        s.send(path_str)
        s.settimeout(5) # five seconds ought to be enough
        try:
            print s.recv(4096)
        except timeout:
            print "Timeout -- waited 5 seconds\n"    
            
    def test3(self, host, path="/"):
        print "## Test 3: Attempting to fragment: Testing Same IP, actual Virtual Host, fragmented packet"
        s = socket()
        s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        s.connect((host, 80))
        path_str = "GET %s HTTP/1.1\r\n" % path
        s.send(path_str)
        time.sleep(0.2) # Sleep for a bit to ensure that the next packets goes through separately.
        s.send("Host: "+host[0:2])
        time.sleep(0.2)
        s.send(host[2:]+"\r\n\r\n")
        try:
            print s.recv(4096)
        except timeout:
            print "Timeout -- waited 5 seconds\n"  
            
def getips(host):
    ips = os.popen('nslookup '+host).readlines()
    result = []
    for i in ips:
        if re.match('Address: ', i):
            current = re.sub('Address: ', '', i)
            current = re.sub('\n', '', current)
            result.append(current)
    return result
    
def testsingle(host, path="/"):
    run = test()
    run.test1(host, path="/") 
    run.test2(host, path="/") 
    run.test3(host, path="/")
    
def testall(host, path="/"):
    ips = getips(host)                                                  
    if len(ips) > 0:
        for i in ips:
            testsingle(i, path="/")

"""
credit: https://blogs.oracle.com/ksplice/entry/learning_by_doing_writing_your
"""            
def traceroute(host):
    print "## Try to trace route to target"
    dest_addr = gethostbyname(host)
    port = 33434
    max_hops = 30
    icmp = getprotobyname('icmp')
    udp = getprotobyname('udp')
    ttl = 1
    while True:
        recv_socket = socket(AF_INET, SOCK_RAW, icmp)
        send_socket = socket(AF_INET, SOCK_DGRAM, udp)
        send_socket.setsockopt(SOL_IP, IP_TTL, ttl)
        recv_socket.bind(("", port))
        send_socket.sendto("", (host, port))
        curr_addr = None
        curr_name = None
        try:
            _, curr_addr = recv_socket.recvfrom(512)
            curr_addr = curr_addr[0]
            try:
                curr_name = gethostbyaddr(curr_addr)[0]
            except error:
                curr_name = curr_addr
        except error:
            pass
        finally:
            send_socket.close()
            recv_socket.close()

        if curr_addr is not None:
            curr_host = "%s (%s)" % (curr_name, curr_addr)
        else:
            curr_host = "*"
        print "%d\t%s" % (ttl, curr_host)

        ttl += 1
        if curr_addr == dest_addr or ttl > max_hops:
            break            
           
def main():
    parser = argparse.ArgumentParser(
        prog="testfilter.py",
        description="Scripts to test for presence of censorship and packet filters")
    parser.add_argument('--host', help='Target Hostname', required=True, metavar='hostname')
    parser.add_argument('--tryall', help='Try all IPs returned by DNS lookup', metavar='1')
    parser.add_argument('--traceroute', help='Try to trace route to target host, require root access', 
        metavar='1')
    parser.add_argument('--path', help='Set the path used to query', metavar='/')
    arguments = parser.parse_args(namespace=target)
 
    if target.tryall is None:
        testsingle(target.host, target.path) 
        if target.traceroute is not None:
            traceroute(target.host, target.path)
    else:
        testall(target.host, target.path)
        if target.traceroute is not None:
            traceroute(target.host)
        
if __name__ == "__main__":
    main()
