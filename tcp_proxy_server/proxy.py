import sys
import socket
import threading

class Color():
    RED = "\033[1;31m"
    BLUE = "\033[1;34m"
    CYAN = "\033[1;36m"
    GREEN = "\033[0;32m"
    RESET = "\033[0;0m"
    BOLD = "\033[;1m"
    REVERSE = "\033[;7m"
    YELLOW = "\033[93m"


def server_loop(local_host,local_port,remote_host,remote_port,receive_first):

    # tao object socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # listen port
        server.bind((local_host,local_port))
    except:

         print Color.RED + "[!] Failed Listen on %s:%d %s" % (local_host,local_port, Color.RESET)
         sys.exit(0)

    print  Color.BLUE + "[*] Successed Listening on %s:%d %s" % (local_host, local_port, Color.RESET)

    # listen port
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # print out the local connection information
        print Color.BOLD + "[**] %s:%d (CLIENT)--> %s:%d (SOCK) %s" %(addr[0], addr[1], local_host, local_port,
                                                                   Color.RESET)
        # start a thread to talk to the remote host
        proxy_thread = threading.Thread(target=proxy_handler, args = (client_socket, remote_host, remote_port, receive_first))
        proxy_thread.start()

def hexdump(src, length=16):
    result = []
    digits = 4 if isinstance(src, unicode) else 2
    for i in xrange(0, len(src), length):
        s = src[i:i + length]
        hexa = b' '.join(["%0*X" % (digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b"%04X  %-*s   %s" % (i, length * (digits + 1), hexa, text) )

    print Color.CYAN + b'\n'.join(result) + Color.RESET

def receive_from(connection):

    buffer = ""
    ## set connection time out la 2
    # connection.settimeout(0.1)
    # try:
    #     # keep reading into the buffer until there's no more data or we time out
    #     while True:
    #         data = connection.recv(4096)
    #         if not data:
    #             break
    #         buffer += data
    # except:
    #     pass

    buffer += connection.recv(4096)
    return buffer

# sua request tu local toi remote
def request_handler(buffer):
   #modify tung packet
   buffer = buffer.replace("<MTO:#> ", "")
   print buffer
   return buffer

#modify respone tu remote toi local
def response_handler(buffer):
   # modify tung packet
   return buffer

def proxy_handler(client_socket, remote_host, remote_port, receive_first):

    # ket noi toi remote host
    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket.connect((remote_host, remote_port))

    # nhan data tu remote neu la true neu can thiet
    if receive_first:

        # nhan data tu remote socket
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

        # respone handler sua packet goi ve client local
        remote_buffer = response_handler(remote_buffer)

        # neu co data thi goi ve cho client
        if len(remote_buffer):
            print Color.YELLOW + "[<==] Sending %d bytes to localhost. %s" % (len(remote_buffer), Color.RESET)
            client_socket.send(remote_buffer)

    # tao loop doc tu local
    # goi toi remote va goi toi local

    while True:

        # nhan data tu client local
        local_buffer = receive_from(client_socket)
        if len(local_buffer):
            print Color.YELLOW + "[==>] Received %d bytes from localhost. %s" % (len(local_buffer), Color.RESET)
            hexdump(local_buffer)

            # sua request cua client local
            local_buffer = request_handler(local_buffer)

            # forward request toi remote
            remote_socket.send(local_buffer)
            print Color.YELLOW + "[==>] Sent to remote. %s" % Color.RESET

        # nhan respone tu remote
        remote_buffer = receive_from(remote_socket)

        if len(remote_buffer):
            print Color.YELLOW + "[<==] Received %d bytes from remote. %s" % (len(remote_buffer), Color.RESET)
            hexdump(remote_buffer)

            # handler respone cua remote tra ve
            remote_buffer = response_handler(remote_buffer)

            # goi respone ve client local
            client_socket.send(remote_buffer)
            print Color.YELLOW +  "[<==] Sent to localhost. %s" % Color.RESET

        # if no more data on either side, close the connections
        if not len(local_buffer) or not len(remote_buffer):
           client_socket.close()
           remote_socket.close()
           print "[*] No more data. Closing connections."
           break


def main():
    #parse command line
    if len(sys.argv[1:]) != 5:
        print "Usage: ./proxy.py [localhost] [localport] [remotehost] [remoteport][receive_first]"

        print "Example: ./proxy.py 127.0.0.1 9000 10.12.132.1 9000 True"
        sys.exit(0)

    # cai port local
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    # cai port remote
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    # this tells our proxy to connect and receive data
    receive_first = sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

        # start server
    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

if __name__ == '__main__':
    #main()
    server_loop("127.0.0.1", 9999, "172.16.227.136", 9999, "True")

