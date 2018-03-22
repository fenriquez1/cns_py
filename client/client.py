import sys
import socket

# Get command line arguments and assign to global variables
SERVER_NAME = sys.argv[1]
PORT = int(sys.argv[2])
PASSWORDS = sys.argv[3:6]
PASSWORD1 = sys.argv[3]
PASSWORD2 = sys.argv[4]
PASSWORD3 = sys.argv[5]
OUTFILE = sys.argv[6]


def sendPassword(sock, pwd):
    response = bytearray()
    passLength = len(pwd)
    response.extend(bytes([3,0]))
    response.extend(passLength.to_bytes(4, byteorder='little'))
    response.extend(bytes(pwd, 'utf-8'))
    sock.sendto(response, (SERVER_NAME, PORT))

########################## START CONNECT TO SERVER ############################

def connectToServer(sock):
    # Send Join Request
    join = bytearray([1,0,0,0,0,0])
    sock.sendto(join, (SERVER_NAME, PORT))

    passReqCount = 0

    while True:
        data = sock.recv(1010)
        print(data)
        header = int.from_bytes(data[0:2], byteorder='little')
        if header == 2: # PASS_REQ
            sendPassword(sock, PASSWORDS[passReqCount])
            passReqCount += 1
        elif header == 4: #PASS_ACCEPT
            # Empty case needed to catch the accept, otherwise it will default
            print("PASS_ACCEPT")
        else:
            print("ABORT")
            exit(1)

########################## START CONNECT AND LISTEN ###########################

################################# START MAIN ##################################

def main():
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    connectToServer(sock)

main()