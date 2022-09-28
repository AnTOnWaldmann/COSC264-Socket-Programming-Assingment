"""
    Author: Anton Waldmann
    Date: 12/08/2022
    Filename: Client.py
    Description: COSC264 Assignment 1 Client Code
    Call Format: python3 Client.py <date/time> <address> <portNo>
    Note: Use address 127.0.0.1 for local host

"""
import socket
import select
import sys

def main():
    """Client Main Method"""

    request_type, addrinfo, port_num = get_client_args()

    #Create Client Socket
    try:
        client_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    except socket.error as err:
        print("Error Creating Socket: " + (err.args[1]))
        sys.exit("Client Exited")

    #Create request packet based on request type
    if request_type =='date':
        packet = compose_dt_request_packet(1)

    elif request_type == 'time':
        packet = compose_dt_request_packet(2)

    else:
        print("Invalid Request Type")
        client_socket.close()
        sys.exit("Client Exited")

    print("*Client Started*")

    #Send request to server
    try:
        client_socket.sendto(packet,(addrinfo[0],port_num))
        print("Request Sent!")

    except ConnectionResetError:
        print("Connection Error: No Server Found")
        client_socket.close()
        sys.exit("Client Exited")

    except socket.error as err:
        print("Error Sending Packet: " + err.args[1])
        client_socket.close()
        sys.exit("Client Exited")

    #Wait for response 1 second
    print("Waiting for a response...")
    readable = select.select([client_socket], [], [] , 1)[0]

    if len(readable) > 0:
        for received in readable:
            print("Response Received!")
            try:
                packet = received.recvfrom(1024)[0]

            except ConnectionResetError:
                print("Connection Error: No Server Found")
                client_socket.close()
                sys.exit("Client Exited")

            except socket.error as err:
                print("Error receiving Packet: " + err.args[1])
                client_socket.close()
                sys.exit("Client Exited")
            decompose_dt_response_packet(packet)
    else:
        print("No response :(")

    print("Client Has Ended")
    client_socket.close()

def decompose_dt_response_packet(packet):
    """Decomposes received packet. Prints error or prints
        whole packet if all conditions are meet.
    """
    #Packet Checking
    if len(packet) < 13:
        print("Invalid Packet Length Received")

    elif (packet[0] << 8) | (packet[1]) != 0x497E:
        print("Invalid Packet MagicNo Received")

    elif (packet[2] <<8) | (packet[3]) != 0x0002:
        print("Invalid Packet Type Received")

    elif (packet[4] <<8) | (packet[5]) != 0x0001 and \
         (packet[4] <<8) | (packet[5]) != 0x0002 and \
         (packet[4] <<8) | (packet[5]) != 0x0003:
        print("Invalid Language Code Received")

    elif (packet[6] <<8) | (packet[7]) > 2100:
        print("Invalid Year Received")

    elif (packet[8]) not in range(1,13):
        print("Invalid Month Received")

    elif (packet[9]) not in range(1,32):
        print("Invalid Day Received")

    elif (packet[10]) not in range(24):
        print("Invalid Hour Received")

    elif (packet[11]) not in range(60):
        print("Invalid Minute Received")

    elif len(packet) != 13 + (packet[12]):
        print("Invalid Packet Sum Length Received")

    else:
        #Print whole packet
        print("Packet Contents")
        print(f"Magic Number: 0x{(packet[0] << 8) | (packet[1]):04X}")
        print(f"Packet Type: 0x{(packet[2] << 8) | (packet[3]):04X}")
        print(f"Language Code: 0x{(packet[4] << 8) | (packet[5]):04X}")
        print(f"Year: {(packet[6] << 8) | (packet[7])}")
        print(f"Month: {packet[8]}")
        print(f"Day: {packet[9]}")
        print(f"Hour: {packet[10]}")
        print(f"Minute: {packet[11]}")
        print(f"Length: {packet[12]}")
        print(f"Text: {packet[13:].decode('utf-8')}")

def compose_dt_request_packet(request_type):
    """Creates a request packet to be sent to server"""

    if request_type in [1,2]:
        magic_num = 0x497E
        packet_type = 0x0001
        packet = bytearray(6)

        packet[0] = (magic_num >> 8)
        packet[1] = (magic_num & 0xFF)

        packet[2] = (packet_type >> 8)
        packet[3] = (packet_type & 0xFF)

        packet[4] = (request_type >> 8)
        packet[5] = (request_type & 0xFF)

        return packet
    print("Invalid Request Type")
    sys.exit("Client Exited")

def get_client_args():
    """Performs checks on provided args and returns client parameters"""

    #Check 3 args have been received
    if len(sys.argv) == 4:
        request_type = sys.argv[1]
        address = sys.argv[2]
        port_num = int(sys.argv[3])

        #Check request type correct
        if request_type not in ('date','time'):
            print("Enter 'date' or 'time' for the 1st parameter request type")
            print("Format: python3 Client.py <date/time> <address> <portNo>")
            sys.exit("Client Exited")

        #Check if address given is correct
        try:
            addrinfo = socket.getaddrinfo(address,port_num)[0][-1]

        except socket.gaierror:
            print("Invalid Address")
            print("Format: python3 Client.py <date/time> <address> <portNo>")
            sys.exit("Client Exited")

        #Check port num range
        if port_num < 1024 or port_num > 64000:
            print("Port value out of range 1,024 - 64,000")
            print("Format: python3 Client.py <date/time> <address> <portNo>")
            sys.exit("Client Exited")

    else:
        print("Please provide all parameters")
        print("Format: python3 Client.py <date/time> <address> <portNo>")
        sys.exit("Client Exited")
    return request_type, addrinfo, port_num

if __name__ == "__main__":
    main()
