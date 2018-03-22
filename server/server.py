import sys
import socket
import os

# Get command line arguments and assign to global variables
PORT = int(sys.argv[1])
PASSWORD = sys.argv[2]
FILE_PATH = sys.argv[3]

############################## START SEND FILE ################################

def sendFile(sock, addr):
    fileInfo = os.stat(FILE_PATH)
    size = fileInfo.st_size

    fd = os.open(FILE_PATH, os.O_RDONLY)
    print(size)
    i = 0
    while i < size:
        data = os.read(fd, 1000)
        response = bytearray()
        response.extend(bytes([5,0]))
        pyldLength = len(data)
        response.extend(pyldLength.to_bytes(4, byteorder='little'))
        response.extend(data)
        sock.sendto(response, addr)
        i += pyldLength


############################## END SEND FILE ################################

############################ START CHECK PASSWORD #############################

def checkPassword(sock, addr, data):
    pyldLength = int.from_bytes(data[0:4], byteorder='little')
    password = str(data[4:pyldLength+4], 'utf-8')
    print(password, PASSWORD)
    if password == PASSWORD:
        print("PASSWORD ACCEPTED")
        sendFile(sock, addr)

############################# END CHECK PASSWORD ##############################

########################### START REQUEST PASSWORD ############################

def requestPassword(sock, addr):
    passRequest = bytearray([2,0,0,0,0,0])
    sock.sendto(passRequest, addr)
    
############################ END REQUEST PASSWORD #############################

########################## START CONNECT AND LISTEN ###########################

def connectAndListen(sock):
    passRespCount = 0
    while True:
        data, addr = sock.recvfrom(1010)
        print(data)

        header = int.from_bytes(data[0:2], byteorder='little')
        if header == 1: # JOIN_REQ
            requestPassword(sock, addr)
        elif header == 3: # PASS_RESP
            checkPassword(sock, addr, data[2:])
            passRespCount += 1
            if passRespCount < 3:
                requestPassword(sock, addr)
            else:
                reject = bytearray([7,0,0,0,0,0])
                sock.sendto(reject, addr)
                print("ABORT")
                exit(1)

########################### END CONNECT AND LISTEN ############################

################################# START MAIN ##################################

def main():
    # Create socket and bind to it
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', PORT))

    connectAndListen(sock)

main()
