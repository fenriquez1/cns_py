#!/usr/bin/env python3
import sys
import socket
import os
import hashlib

# Get command line arguments and assign to global variables
USAGE = "Usage: ./server.py <port> <password> <input file>"
try:
    SERVER_NAME = sys.argv[1]
    PORT = int(sys.argv[2])
    PASSWORDS = sys.argv[3:6]
    PASSWORD1 = sys.argv[3]
    PASSWORD2 = sys.argv[4]
    PASSWORD3 = sys.argv[5]
    OUTFILE = sys.argv[6]
except (ValueError, IndexError):
    print(USAGE)
    exit(1)

############################ START CHECK DIGEST ###############################

def checkDigest(buff):
    # Get size of file
    fileInfo = os.stat(OUTFILE)
    size = fileInfo.st_size
    # Read entire file
    fd = os.open(OUTFILE, os.O_RDONLY)
    data = os.read(fd, size)
    # Get message digest of file data
    m = hashlib.sha1(data)
    digest = m.digest()
    # Get digest sent from server
    pyldLength = int.from_bytes(buff[0:4], byteorder='little')
    pyld = buff[4:]
    if pyldLength != len(pyld):
        return False
    if len(digest) != pyldLength:
        return False
    for i in range(pyldLength):
        if digest[i] != pyld[i]:
            return False

    return True

############################## END CHECK DIGEST ###############################
############################ START SEND PASSWORD ##############################

def sendPassword(sock, pwd):
    response = bytearray()
    passLength = len(pwd)
    response.extend(bytes([3,0]))
    response.extend(passLength.to_bytes(4, byteorder='little'))
    response.extend(bytes(pwd, 'utf-8'))
    sock.sendto(response, (SERVER_NAME, PORT))

############################# END SEND PASSWORD ###############################
########################## START CONNECT TO SERVER ############################

def connectToServer(sock):
    status = ""
    # Send Join Request
    join = bytearray([1,0,0,0,0,0])
    sock.sendto(join, (SERVER_NAME, PORT))

    flags = os.O_CREAT | os.O_RDWR
    fd = os.open(OUTFILE, flags, mode=0o660, dir_fd=None)
    
    passReqCount = 0

    while True:
        buff = sock.recv(1010)
        header = int.from_bytes(buff[0:2], byteorder='little')
        if header == 2: # PASS_REQ
            sendPassword(sock, PASSWORDS[passReqCount])
            passReqCount += 1
        elif header == 4: #PASS_ACCEPT
            # Empty case needed to catch the accept, otherwise it will default
            print("PASS_ACCEPT")
        elif header == 5: #DATA
            data = buff[6:]
            os.write(fd, data)
        elif header == 6: # TERMINATE
            if checkDigest(buff[2:]) == True:
                status = "OK"
            else:
                status = "ABORT"
            break
        else:
            status = "ABORT"
            break
    return status

############################ END CONNECT TO SERVER ############################
################################# START MAIN ##################################

def main():
    # Create socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print(connectToServer(sock))
    sock.close()

main()