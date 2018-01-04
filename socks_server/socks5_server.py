# -*- coding: utf-8 -*-
# __Author__ : dongvt
# __Email__ : mrneodiablo@gmail.com
# __Github__ : mrneodiablo

# Tát nước sau mưa: Haha
# Nguồn : https://en.wikipedia.org/wiki/SOCKS
# Socks protocol thuộc layer 5 trong OSI nha
"""
đây là script basic  chỉ hỗ trợ socks noauth và TCP, không thể UDP,BIND haha, ngu vãi cặt


script sẽ tạo socks server sử dụng sử dụng native python , không cần cài thêm lib ngoài

socks 5 là chuẩn mở rộng của socks 4 hỗ trợ UDP, IPv6, DNS lookup:

socks5 handshake

[CLIENT]                             [SERVER SOCKS]
  
 connect và gởi greeting, 
 bao gồm phương thức chứng thực
  1/ --------------------------------------------->
                       
                            Server chọn 1 trong các 
                            phương thức
  2/ <---------------------------------------------
   
   
   
              1 số messages trao đổi
              tùy vào phương thức xác thực
  3/ <--------------------------------------------->
  
  
   
 client gửi một yêu cầu kết nối 
  tương tự như SOCKS4.
  4/ ---------------------------------------------->
  
  
                            server respone như SOCKS4
  5/ <---------------------------------------------


SOCKS 5 PROTOCOL

1/ client send greeting
|-----------------------------------------------|
|  socks version: 5       (1 byte)              |
|-----------------------------------------------|  
| authentication methods count: 1 (1 byte)      |
|-----------------------------------------------|
|  authentication methods: 0 noauthen  (1 byte) |
|-----------------------------------------------|

authentication methods: 
    - 0 : no authen
    - 1: GSSAPI
    - 2: Username/password
    - 3-127: IANA
    - 127-254: Phương pháp dành riêng cho cá nhân, ( có thể chế chỗ này haha )


2/ Server chọn các phương thức

-----------Nếu No Authen method------------------

|-----------------------------------------------|
|  socks version: 5       (1 byte)              |
|-----------------------------------------------|  
| chosen authentication method: 0 (1 byte)      |
| chọn phương thức xác thực là 0(noauthen)      |
|  0xFF(255) không có phương thức xác thục chấp |
| nhận                                          | 
|-----------------------------------------------|

3/ -----------Nếu Authen meothod---------------------
 
 Sau khi chọn phương thức xác thực user/password(2) ở trên thì client sẽ gởi gói thông tin userpass

client  sent
|-----------------------------------------------|
|  socks version: 5       (1 byte)              |
|-----------------------------------------------|  
| username length:   (1 byte)                   |
|-----------------------------------------------|
| username:         (1–255 bytes)               |
|-----------------------------------------------| 
| password length:   (1 byte)                   |
|-----------------------------------------------|
| password:         (1–255 bytes)               |
|-----------------------------------------------|


server respone
|-----------------------------------------------|
|  socks version: 5       (1 byte)              |
|-----------------------------------------------|  
| status code: 0 (1 byte)                       |    
|-----------------------------------------------|
 - status code
    0 :success
    !0 : failure connect close
 
 
 4/ CLient yêu cầu kết nối tới target

|-----------------------------------------------|
|  socks version: 5       (1 byte)              |
|-----------------------------------------------|  
|  command code: 1/2/3   (1 byte)               |
|-----------------------------------------------|
|  reserved:  0       (1 bytes)                 |
|-----------------------------------------------| 
|  address type:1/3/4   (1 byte)                |
|-----------------------------------------------|
|  remote address:                              |
|-----------------------------------------------|    
|  remote port:  (2 bytes)                      |
|-----------------------------------------------|

 - command code:
     1: establish a TCP/IP stream connection
     2: establish a TCP/IP port binding
     3:  associate a UDP port
     
 - address type:
     1: ipv4
     3: domain
     4: ipv6

5/ server respone
|-----------------------------------------------|
|  socks version: 5       (1 byte)              |
|-----------------------------------------------|  
|  status: 0-8   (1 byte)               |
|-----------------------------------------------|
|  reserved:  0       (1 bytes)                 |
|-----------------------------------------------| 
|  address type:1/3/4   (1 byte)                |
|-----------------------------------------------|
|  remote address:                              |
|-----------------------------------------------|    
|  remote port:  (2 bytes)                      |
|-----------------------------------------------|

  - status:
     0: request granted
     1: general failure
     2: connection not allowed by ruleset
     3: network unreachable
     4: host unreachable
     5: connection refused by destination host
     6: TTL expired
     7: command not supported / protocol error
     8: address type not supported
   - address type:
     1: ipv4
     3: domain
     4: ipv6   
         
"""

import socket
import threading
import sys




# color for output
class bcolors():
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


class SOCKsDefault(object):

    # define socks server
    SOCKS_VERSION = 5
    ALLOWED_METHOD = [0]

    # command in byte step 4
    CONNECT = 1
    BIND = 2
    UDP_ASSOCIATE = 3

    # adress type
    IPV4 = 1
    DOMAINNAME = 3
    IPV6 = 4

    # respone define
    CONNECT_SUCCESS = 0
    RSV = 0
    BNDADDR = "\x00" * 4
    BNDPORT = "\x00" * 2


class SOCKsError(object):

    # define error
    ERROR_VERSION = bcolors.FAIL +"[-] Client version error!" + bcolors.ENDC
    ERROR_METHOD =  bcolors.FAIL +"[-] Client method error!" + bcolors.ENDC
    ERROR_CMD = bcolors.FAIL + "[-] Client command error!" + bcolors.ENDC
    ERROR_ATYPE = bcolors.FAIL + "[-] Client address error!" + bcolors.ENDC

def handle(buffer):
    return buffer

def transfer(src, dst):
    src_name = src.getsockname()
    src_address = src_name[0]
    src_port = src_name[1]

    dst_name = dst.getsockname()
    dst_address = dst_name[0]
    dst_port = dst_name[1]


    print bcolors.OKGREEN+"[+] Starting transfer [%s:%d] => [%s:%d]" % (src_name, src_port, dst_name, dst_port)+bcolors.ENDC

    while True:

        # nhận data
        try:
            buffer = src.recv(0x1000)
        except Exception as e:
            print bcolors.WARNING + "[-] Error recv  %s:%s...%s" % (src_address, src_port, e) + bcolors.ENDC
        if not buffer:
            print bcolors.WARNING+"[-] No data received! Breaking..."+bcolors.ENDC
            break
        print bcolors.OKGREEN +"[+] %s:%d => %s:%d => Length : [%d]" % (src_address, src_port, dst_address, dst_port, len(buffer)) + bcolors.ENDC
        try:
            dst.send(handle(buffer))
        except Exception as e:
            print bcolors.WARNING + "[-] Error send %s:%s...%s" %(dst_address, dst_port,e) + bcolors.ENDC

    print  bcolors.WARNING +"[+] Closing connecions! [%s:%d]" % (src_address, src_port) + bcolors.ENDC
    src.close()
    print  bcolors.WARNING +"[+] Closing connecions! [%s:%d]" % (dst_address, dst_port) + bcolors.ENDC
    dst.close()


# phương thức kiểm tra thông tin gói greeting client gởi lên
def socks_selection(socket):
    """
    kiểm tra gói greeting client gởi lên ở bước 2
    SOCKS_VERSION có hổ trợ không
    AUTH_METHOD có hổ trợ không
    
    :param socket: 
    :return: 
     - tất cả có hổ trợ : return object socket, true
     - không hỗ trợ return false
    """

    # TODO: nhận gói tin với buffer là 1 byte ( byte đầu của gói request từ client) là socks version
    client_version = ord(socket.recv(1))
    print bcolors.OKBLUE +"[+] client version : %d" % (client_version) + bcolors.ENDC
    if not client_version == SOCKsDefault.SOCKS_VERSION:
        socket.shutdown(socket.SHUT_RDWR)
        socket.close()
        return (False, SOCKsError.ERROR_VERSION)

    #TODO: lấy byte tiếp theo là authen method count
    support_method_number = ord(socket.recv(1))
    print bcolors.OKBLUE +"[+] Client Supported method number : %d" % (support_method_number) + bcolors.ENDC
    support_methods = []
    for i in range(support_method_number):

        #TODO: lấy byte tiêp theo là authentication methods
        # hàm ord chuyển ký tự thành số trong asii
        # hàm chr chuyển số thành ký tự
        method = ord(socket.recv(1))
        print bcolors.OKBLUE +"[+] Client Method : %d" % (method) + bcolors.ENDC
        support_methods.append(method)
    selected_method = None
    for method in SOCKsDefault.ALLOWED_METHOD:
        if method in support_methods:
            selected_method = 0
    if selected_method == None:
        socket.shutdown(socket.SHUT_RDWR)
        socket.close()
        return (False, SOCKsDefault.ERROR_METHOD)
    print bcolors.OKBLUE+"[+] Server select method : %d" % (selected_method)+bcolors.ENDC

    #respone gói tin access no authen từ server
    response = chr(SOCKsDefault.SOCKS_VERSION) + chr(selected_method)
    socket.send(response)
    return (True, socket)


# phương thức ngận request từ client sau khi handshake
def socks_request(local_socket):

    # Bước 4 nhận gói request từ client

    # byte đầu tiên là version
    client_version = ord(local_socket.recv(1))
    print bcolors.OKBLUE +"[+] client version : %d" % (client_version)+ bcolors.ENDC
    if not client_version == SOCKsDefault.SOCKS_VERSION:
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, SOCKsError.ERROR_VERSION)

    # byte tiếp theo trong gói từ client là CMD
    cmd = ord(local_socket.recv(1))
    if cmd == SOCKsDefault.CONNECT:
        print bcolors.OKBLUE+"[+] CONNECT request from client"+bcolors.ENDC

        # TODO: lấy byte thứ 3 reserved nên bằng 0
        rsv = ord(local_socket.recv(1))
        if rsv != 0:
            local_socket.shutdown(socket.SHUT_RDWR)
            local_socket.close()
            return (False, SOCKsError.ERROR_RSV)
        atype = ord(local_socket.recv(1))
        if atype == SOCKsDefault.IPV4:

            # lấy dest từ gói tim
            dst_address = ("".join(["%d." % (ord(i)) for i in local_socket.recv(4)]))[0:-1]
            print bcolors.OKBLUE+"[+] IPv4 : %s" % (dst_address)+bcolors.ENDC

            # lây source từ gói tin
            dst_port = ord(local_socket.recv(1)) * 0x100 + ord(local_socket.recv(1))
            print bcolors.OKBLUE +"[+] Port : %s" % (dst_port) + bcolors.ENDC

            # TODO: Sau khi lấy được bắt đầu tạo socket gọi tới remote server hihi
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                print bcolors.OKGREEN+"[+] Connecting : %s:%s" % (dst_address, dst_port)+bcolors.ENDC
                remote_socket.connect((dst_address, dst_port))

                # gởi gói respone về cho client
                # Chú ý gói respone về BINADDR và BNDPORT là 0x00 với byte đủ
                response = ""
                response += chr(SOCKsDefault.SOCKS_VERSION)
                response += chr(SOCKsDefault.CONNECT_SUCCESS)
                response += chr(SOCKsDefault.RSV)
                response += chr(SOCKsDefault.IPV4)
                response += SOCKsDefault.BNDADDR
                response += SOCKsDefault.BNDPORT
                local_socket.send(response)

                #  [client] <----------->[local_socket]... tranfer...[remote_socket] <---------->[remote]
                #
                print bcolors.OKGREEN +"[+] Tunnel connected! Tranfering data..."+bcolors.ENDC

                # thread 1: từ local tới tới remote
                r = threading.Thread(target=transfer, args=(
                    local_socket, remote_socket))
                r.start()

                # thread 2: từ remote trả về local
                s = threading.Thread(target=transfer, args=(
                    remote_socket, local_socket))
                s.start()
                return (True, (local_socket, remote_socket))

            except socket.error as e:
                print e
                remote_socket.shutdown(socket.SHUT_RDWR)
                remote_socket.close()
                local_socket.shutdown(socket.SHUT_RDWR)
                local_socket.close()
        elif atype == SOCKsDefault.DOMAINNAME:
            domainname_length = ord(local_socket.recv(1))
            domainname = ""
            for i in range(domainname_length):
                domainname += (local_socket.recv(1))
            print "[+] Domain name : %s" % (domainname)
            dst_port = ord(local_socket.recv(1)) * 0x100 + ord(local_socket.recv(1))
            print "[+] Port : %s" % (dst_port)
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                print "[+] Connecting : %s:%s" % (domainname, dst_port)
                remote_socket.connect((domainname, dst_port))
                response = ""
                response += chr(SOCKsDefault.SOCKS_VERSION)
                response += chr(SOCKsDefault.CONNECT_SUCCESS)
                response += chr(SOCKsDefault.RSV)
                response += chr(SOCKsDefault.IPV4)
                response += SOCKsDefault.BNDADDR
                response += SOCKsDefault.BNDPORT
                local_socket.send(response)
                print "[+] Tunnel connected! Tranfering data..."
                r = threading.Thread(target=transfer, args=(
                    local_socket, remote_socket))
                r.start()
                s = threading.Thread(target=transfer, args=(
                    remote_socket, local_socket))
                s.start()
                return (True, (local_socket, remote_socket))
            except socket.error as e:
                print e
                remote_socket.shutdown(socket.SHUT_RDWR)
                remote_socket.close()
                local_socket.shutdown(socket.SHUT_RDWR)
                local_socket.close()
        elif atype == SOCKsDefault.IPV6:
            dst_address = int(local_socket.recv(4).encode("hex"), 16)
            print "[+] IPv6 : %x" % (dst_address)
            dst_port = ord(local_socket.recv(1)) * 0x100 + ord(local_socket.recv(1))
            print "[+] Port : %s" % (dst_port)
            remote_socket = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            remote_socket.connect((dst_address, dst_port))
            local_socket.shutdown(socket.SHUT_RDWR)
            local_socket.close()
            return (False, SOCKsError.ERROR_ATYPE)
        else:
            local_socket.shutdown(socket.SHUT_RDWR)
            local_socket.close()
            return (False, SOCKsError.ERROR_ATYPE)
    elif cmd == SOCKsDefault.BIND:
        # TODO: Hiện tại command BIND thì script vấn chưa hỗ trợ nhé, rãnh thì tao sẽ code thêm, giờ đéo
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, SOCKsError.ERROR_CMD)
    elif cmd == SOCKsDefault.UDP_ASSOCIATE:
        # TODO:  Hiện tại command UDP thì script vấn chưa hỗ trợ nhé, rãnh thì tao sẽ code thêm, giờ đéo
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, SOCKsError.ERROR_CMD)
    else:
        local_socket.shutdown(socket.SHUT_RDWR)
        local_socket.close()
        return (False, SOCKsError.ERROR_CMD)
    return (True, local_socket)



# build socket listen port cho socks server
def server(local_host, local_port, max_connection):

    """
    
    phương thức socks_selection đêt kiểm tra method auth
    
    :param local_host: "127.0.0.1"
    :param local_port:  1080
    :param max_connection: 1000
    :return: 
    Kiểm tra xem client gởi lên có authen method trong list của socks server không
      - có action
      - không drop
    """
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((local_host, local_port))
        server_socket.listen(max_connection)
        print bcolors.OKBLUE +  '[+] Server started [%s:%d]' % (local_host, local_port) + bcolors.ENDC
        while True:
            local_socket, local_address = server_socket.accept()
            print bcolors.OKBLUE +'[+] Detect connection from [%s:%s]' % (local_address[0], local_address[1]) + bcolors.ENDC
            result = socks_selection(local_socket)
            if not result[0]:
                print bcolors.FAIL+"[-] socks selection error!" + bcolors.ENDC
                break
            result = socks_request(result[1])
            if not result[0]:
                print bcolors.FAIL +"[-] socks request error!" + bcolors.ENDC
                break
                # local_socket, remote_socket = result[1]
                # TODO : loop all socket to close...
        print bcolors.FAIL +"[+] Releasing resources..." + bcolors.ENDC
        local_socket.close()
        print bcolors.FAIL +"[+] Closing server..." + bcolors.ENDC
        server_socket.close()
        print bcolors.FAIL +"[+] Server shuted down!" + bcolors.ENDC
    except  KeyboardInterrupt:
        print bcolors.OKBLUE +' Ctl-C stop server' + bcolors.ENDC
        try:
            local_socket.close()
        except:
            pass
        try:
            server_socket.close()
        except:
            pass
        return


def main():
    if len(sys.argv) != 3:
        print "Usage : "
        print "\tpython %s [L_HOST] [L_PORT]" % (sys.argv[0])
        print "Example : "
        print "\tpython %s 127.0.0.1 1080" % (sys.argv[0])
        exit(1)
    LOCAL_HOST = sys.argv[1]
    LOCAL_PORT = int(sys.argv[2])
    MAX_CONNECTION = 0x10
    server(LOCAL_HOST, LOCAL_PORT, MAX_CONNECTION)


if __name__ == "__main__":
    main()