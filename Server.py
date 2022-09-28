"""
    Author: Anton Waldmann
    Date: 12/08/2022
    Filename: Server.py
    Description: COSC264 Assignment 1 Server Code
    Call Format: python3 Server.py Port# port# port#

"""
import select
import datetime
import sys
import socket

#Global Variable Ip Address for easy access
ADDRESS = ''  # Shortcut for INADDR_ANY

def main():
    """main method of the server program"""

    port_tuple = get_server_args()

    socket_english, socket_tereo, socket_german = create_bind_sockets(port_tuple)

    #lists for select() to monitor
    is_incoming = [socket_english, socket_tereo, socket_german]
    print("*Server started*\nWaiting for a request...")

    #Start infinite loop waiting for incoming packets from bound sockets
    while True:

        readable = select.select(is_incoming,[],[],1)[0]

        #Process received packets
        for received in readable:
            print("Request Received!")

            try:
                packet, addr = received.recvfrom(1024)

            except ConnectionResetError:
                print("Connection Error: No Server Found\nDiscarded")
                continue

            except socket.error as err:
                print("Error receiving packet: " + err.args[1])
                print("Discarded")
                continue

            # Decompose request packet
            req_type = decompose_dt_request_packet(packet)
            if req_type < 0:
                continue

            #Find what language client wants to receive
            if received == socket_english:
                reply_packet = compose_dt_response_packet(1,req_type)
                reply_socket = socket_english

            elif received == socket_tereo:
                reply_packet = compose_dt_response_packet(2,req_type)
                reply_socket = socket_tereo

            elif received == socket_german:
                reply_packet = compose_dt_response_packet(3,req_type)
                reply_socket = socket_german

            else:
                print("Invalid Socket\nDiscarded")
                continue

            #Invalid String Len
            if reply_packet == -1:
                print("Length of response string out of range\nDiscarded")
                continue

            #Send packet to client
            try:
                reply_socket.sendto(reply_packet,addr)
                print("Response Sent!")

            except ConnectionResetError:
                print("Connection Error: No Server Found\nDiscarded")
                continue

            except socket.error as err:
                print("Error Sending Packet: " + err.args[1])
                print("Discarded")
                continue

def compose_dt_response_packet(language_code,request):
    """Compose the response packet being sent back to the client. Return -1 if text too big"""

    magic_num = 0x497E
    packet_type = 0x0002
    date_time = datetime.datetime.now()
    text = text_create(date_time,language_code)[request-1]
    encoded_text = text.encode('utf-8')
    text_length = len(encoded_text)

    if text_length <= 255:
        #Compose packet
        packet = bytearray(13 + text_length) #Byte array created to exact length

        packet[0] = (magic_num >> 8)
        packet[1] = (magic_num & 0xFF)

        packet[2] = (packet_type >> 8)
        packet[3] = (packet_type & 0xFF)

        packet[4] = (language_code >> 8)
        packet[5] = (language_code & 0xFF)

        packet[6] = (date_time.year >> 8)
        packet[7] = (date_time.year & 0xFF)

        packet[8] = date_time.month
        packet[9] = date_time.day
        packet[10] = date_time.hour
        packet[11] = date_time.minute

        packet[12] = text_length

        for i in range(text_length):
            packet[13+i] = encoded_text[i]

        return packet

    return -1

def text_create(date_time,language_code):
    """Creates text client is wanted to receive"""
    month = date_time.month
    day = date_time.day
    year = date_time.year
    hour = date_time.hour
    minute = date_time.minute

    english_months = {1:"January",2:"February",3:"March",4:"April",5:"May",
                     6:"June", 7:"July", 8:"August",9:"September",
                     10:"October",11:"November",12:"December"}

    tereo_months = {1:"Kohitatea",2:"Hui-tanguru",3:"Poutu-te-rangi",
                   4:"Paenga-whawha ",5:"Haratua",6:"Pipiri", 7:"Hongongoi",
                   8:"Here-turi-koka",9:"Mahuru",10:"Whiringa-a-nuku",
                   11:"Whiringa-a-rangi",12:"Hakihea"}

    german_months = {1:"Januar",2:"Februar",3:"Marz",4:"April",5:"Mai",
                     6:"Juni", 7:"Juli", 8:"August",9:"September",
                     10:"Oktober",11:"November",12:"Dezember"}

    if language_code == 1:
        date_text = f"Today's date is {day} {english_months[month]}, {year}"
        time_text = f"The current time is {hour:02d}:{minute:02d}"

    elif language_code == 2:
        date_text = f"Ko te ra o tenei ra ko {day} {tereo_months[month]}, {year}"
        time_text = f"Ko te wa o tenei wa {hour:02d}:{minute:02d}"

    else:
        date_text = f"Heute ist der {day} {german_months[month]}, {year}"
        time_text = f"Die Uhrzeit ist {hour:02d}:{minute:02d}"

    return (date_text, time_text)

def decompose_dt_request_packet(packet):
    """decomposes received packet are returns the RequestType.
       As well as performing Checks return -1 if fail with a printed error.
    """
    if len(packet) != 6:
        print("Invalid Packet Length\nDiscarded")
        return -1

    if (packet[0] << 8) | (packet[1]) != 0x497E:
        print("Invalid Packet MagicNo\nDiscarded")
        return -1

    if (packet[2] <<8) | (packet[3]) != 0x0001:
        print("Invalid Packet Type\nDiscarded")
        return -1

    if (packet[4] <<8) | (packet[5]) != 0x0001 and \
         (packet[4] <<8) | (packet[5]) != 0x0002:
        print("Invalid Packet Request Type\nDiscarded")
        return -1

    return (packet[4] <<8) | (packet[5]) #Return RequestType

def get_server_args():
    """Performs checks on provided args and returns server parameters"""

     #Check 3 args have been received
    if len(sys.argv) == 4:
        #Retrieve ports users defined ports
        english_port = int(sys.argv[1])
        te_reo_port = int(sys.argv[2])
        german_port = int(sys.argv[3])

        #Arg Requirements checking
        if english_port == te_reo_port or te_reo_port == german_port or \
            english_port == german_port:
            print("Please Enter 3 unique port numbers")
            print("Format: python3 Server.py Port# port# port#")
            sys.exit("Server Exited")

        #Port range check
        for port in [english_port, te_reo_port, german_port]:
            if port < 1024 or port > 64000:
                print("Invalid Port Range. Port must between 1,024 and 64,000")
                print("Format: python3 Server.py Port# port# port#")
                sys.exit("Server Exited")

    else:
        print("Not Enough Arguments Entered!")
        print("Format: python3 Server.py Port# port# port#")
        sys.exit("Server Exited")

    return english_port, te_reo_port, german_port

def create_bind_sockets(port_tuple):
    """create and binds ports from port tuple. """

    #Socket creation
    try:
        socket_english = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        socket_tereo = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        socket_german = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

    except socket.error as err:
        print("Error creating socket: " + err.args[1])
        sys.exit("Server Exited")

    #Binding sockets with ip and user defined ports
    try:
        socket_english.bind((ADDRESS,int(port_tuple[0])))
        socket_tereo.bind((ADDRESS,int(port_tuple[1])))
        socket_german.bind((ADDRESS,int(port_tuple[2])))

    except socket.gaierror:
        print("Address not valid")
        socket_english.close()
        socket_tereo.close()
        socket_german.close()
        sys.exit("Server Exited")

    except socket.error as err:
        print("Error Binding Sockets: " + err.args[1])
        socket_english.close()
        socket_tereo.close()
        socket_german.close()
        sys.exit("Server Exited")

    return socket_english, socket_tereo, socket_german

if __name__ == "__main__":
    main()
