# Authors: Rumen Kasabov, Michael Radke
# CPSC526 - Assignment 3

########################################
########################################
# Proxy server program that creates a tunnel between two connections where data is exchanged with the potential
# for manipulation of the data (for reasons such as MITM attacks).
# Current allows for several different logging options of the data, as well as replacing requested strings of data.
# Logging and replacing is only on server side.
########################################
########################################

import socket
import sys
import datetime
import threading
import select
import re

log_commands = ["-raw", "-strip", "-hex"]

# Thread function that handles tunnel connection between the source and destination addresses
def connection_handler(client_socket, destination_socket, log_option, n_bytes, replace_option, option_one, option_two):

    inputs = [client_socket, destination_socket]

    # Keep connection between source client and destination client alive
    while 1:

        # Returns a subset list from inputs into readable containing incoming data that is buffered
        # and ready to read
        readable, writable, exceptable = select.select(inputs, [], [])

        for sock in readable:

            data = sock.recv(4096)
            modified_data = data

            # If no data provided, we close the current connection stream.
            if not data:
                print("No data provided. Connection closed.")
                client_socket.close()
                destination_socket.close()
                return

            # Check if socket sending data is destination socket and if so, send data to the client
            if sock == destination_socket:

                if replace_option != "":

                    modified_data = replace_data(option_one, option_two, data)

                    # Encode it back
                    modified_data = modified_data.encode()

                if log_option != "":

                    message = log_data(log_option, modified_data, n_bytes)

                    # Loop through the message array, printing each line of data to terminal
                    counter = 0
                    while counter < len(message):

                        print("<--- " + str(message[counter]) + "\n")

                        counter += 1

                client_socket.sendall(data)

            # Otherwise send data from client to the destination
            else:

                if replace_option != "":

                    modified_data = replace_data(option_one, option_two, data)

                    # Encode it back
                    modified_data = modified_data.encode()

                if log_option != "":

                    message = log_data(log_option, modified_data, n_bytes)

                    # Send the source message
                    counter = 0
                    while counter < len(message):

                        print("---> " + str(message[counter]) + "\n")

                        counter += 1

                destination_socket.sendall(data)


def log_data(log_option, data, n_bytes):

    # Decode bytes to string
    data = data.decode("UTF-8")

    # Do nothing, option is raw
    if log_option == "-raw":

        # Split newlines
        message = data.split("\n")

        return message

    # Strip non-printable characters and replace them with dots
    elif log_option == "-strip":

        message = []

        # Using regex to replace all data except for 32 - 126 on the ASCII table with a dot (non printable characters)
        # We consider anything below 32 and above 126 non printable
        data = re.sub(r'[^\x20-\x7E]', '.', data)

        # Split newlines
        message = data.split("\n")

        return message

    elif log_option == "-hex":

        # Initialize input offset
        input_offset = 0x0

        data_length = len(data)

        # Containing final message
        message = []

        # Loop 16 characters at a through data, printing input offset, hex values of each char, and the chars themselves
        # (Equivalent to hexdump -C command in linux)
        while data_length >= 0:

            # Initialize data char and hex char variable
            hex_char = ""
            data_char = ""

            # Format the input offset to a hex number excluding "0x"
            formatted_input_offset = hex(input_offset)[2:]

            # Make sure the hex offset is padded with max eigth 0s
            formatted_input_offset = formatted_input_offset.zfill(8)

            counter = 0
            while counter < 16:

                # Make sure we don't try to increment to an out of range offset in the data (stop when the length
                # reaches 0.x
                if data_length - counter > 0:

                    # Get the first character in the data
                    data_char += data[counter + input_offset]

                    # Get each character up to 16 characters per line and print each as hexadecimal
                    nex_hex_char = hex(ord(data[counter + input_offset]))

                    # Remove '0x' and add a space
                    hex_char += nex_hex_char[2:] + " "

                    if counter == 7:
                        hex_char = hex_char + " "

                counter += 1

            # Get rid of non-printable characters like in strip
            data_char = re.sub(r'[^\x20-\x7E]', '.', data_char)

            message.append(('{0}   {1:50} |{2}|'.format(formatted_input_offset, hex_char, data_char)))

            # Increment the offset to the next 16 hex bytes
            input_offset = input_offset + 0x10

            data_length -= 16

        return message

    # We do -autoN
    else:

        # Final message content
        message = []

        data_length = len(data)

        # Total amount of bytes read from the data
        total_read = 0

        # Loop through the data, splitting it into chunks and re-formatting tabs, carriages, newlines and slashes
        while data_length >= 0:

            # Initialize data char and hex char variable
            hex_char = ""
            data_char = ""

            counter = 0

            # We loop up to the provided chunk of bytes and format it for each line
            while counter < int(n_bytes):

                # Make sure we don't try to increment to an out of range offset in the data
                if data_length - counter > 0:

                    hex_position = int(hex(ord(data[counter + total_read])), 16)

                    # If the char is a printable character within the ascii table (32-126) add it without modification
                    if hex_position >= 32 and hex_position <= 126:

                        # If it is a backslash, change the output format to \\
                        if hex_position == 92:

                            data_char += "\\\\"

                        # Otherwise report raw data
                        else:
                            data_char += data[counter + total_read]

                    else:

                        # If the char head position is that of a newline, report it as \n
                        if hex_position == 10:

                            data_char += "\\n"

                        # Otherwise if char position is that of a tab, report it as \t
                        elif hex_position == 9:

                            data_char += "\\t"

                        # Otherwise if carriage return, report as \r
                        elif hex_position == 13:

                            data_char += "\\r"

                        # Else if its none of the above, get the hexadecimal value of the character and report it as that
                        else:

                            hex_char = hex(ord(data[counter + total_read]))

                            # Remove '0x'
                            hex_char = hex_char[2:]

                            data_char += "\\" + hex_char

                counter += 1

            # Add the chunk to the message array
            message.append(data_char)

            total_read += int(n_bytes)

            # Decrease length of data by N byte chunks on each iteration
            data_length -= int(n_bytes)

        return message


def replace_data(option_one, option_two, data):

    # Decode bytes to string
    data = data.decode("UTF-8")

    # If either replace option given is blank, indicate to user and quit thread
    if option_one == "" or option_two == "":

        print("Please provide valid replace options.\n")
        print("This can include any type of string you wish replaced [optionOne]"
              " within the data with another [optionTwo].\n")
        quit()

    data = data.replace(option_one, option_two)

    return data


if __name__ == "__main__":

    # Initialize localhost, server, and port variables
    HOST = "localhost"
    server = ""
    srcPort = 0
    dstPort = 0

    # Initialize log and replace options variables
    log_option = ""
    n_bytes = ""
    replace_option = ""
    option_one = ""
    option_two = ""

    # Obtaining the command line arguments
    if len(sys.argv) == 8:

        log_option = sys.argv[1]
        replace_option = sys.argv[2]

        # Check whether correct log and replace options have been given
        if log_option[:5] == "-auto":

            # If no specified chunk length given, indicate error
            if len(log_option) == 5:
                print("Please provide a correct log option: '-autoN' requires a non-zero positive chunk byte number N\n")
                quit()

            n_bytes = log_option[5:]

            # If the number of bytes is not a non-zero positive integer, indicate error
            if int(n_bytes) <= 0:
                print(
                    "Invalid number provided: '-autoN' requires a non-zero positive chunk byte number N\n")
                quit()

        # If the logging option provided is not a correct option, indicate to user and quit program
        elif log_option not in log_commands:

            print("Please provide a correct log option.\n")
            quit()

        if replace_option != "-replace":
            print("Please provide a correct replace argument: '-replace'.\n")
            quit()

        option_one = sys.argv[3]
        option_two = sys.argv[4]
        srcPort = sys.argv[5]
        server = sys.argv[6]
        dstPort = sys.argv[7]

    # Else if 7 arguments provided, log option is excluded
    elif len(sys.argv) == 7:

        replace_option = sys.argv[1]
        option_one = sys.argv[2]
        option_two = sys.argv[3]
        srcPort = sys.argv[4]
        server = sys.argv[5]
        dstPort = sys.argv[6]

        if replace_option != "-replace":
            print("Please provide a correct replace argument: '-replace'.\n")
            quit()

    # Else if 5 arguments provided, replace option excluded
    elif len(sys.argv) == 5:

        log_option = sys.argv[1]

        # Check whether correct log and replace options have been given
        if log_option[:5] == "-auto":

            # If no specified chunk length given, indicate error
            if len(log_option) == 5:
                print(
                    "Please provide a correct log option: '-autoN' requires a non-zero positive chunk byte number N\n")
                quit()

            n_bytes = log_option[5:]

            # If the number of bytes is not a non-zero positive integer, indicate error
            if int(n_bytes) <= 0:
                print(
                    "Invalid number provided: '-autoN' requires a non-zero positive chunk byte number N\n")
                quit()

        # If the logging option provided is not a correct option, indicate to user and quit program
        elif log_option not in log_commands:

            print("Please provide a correct log option.\n")
            quit()

        srcPort = sys.argv[2]
        server = sys.argv[3]
        dstPort = sys.argv[4]

    # Else if 4, no replacement options or logging options have been provided
    elif len(sys.argv) == 4:

        srcPort = sys.argv[1]
        server = sys.argv[2]
        dstPort = sys.argv[3]

    # Otherwise, wrong amount of arguments has been provided,
    # indicate error and quit the program
    else:
        print("USAGE: 'python proxy.py [logOptions] -replace [optionOne] [optionTwo] srcPort server dstPort'")
        quit()

    # Create a server socket that will connect to the source client we are obtaining data from
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind it to the source hostname and the source port number
    server_socket.bind((HOST, int(srcPort)))

    # Listen to incoming messages
    server_socket.listen(5)

    print("Port logger running: srcPort=" + srcPort + " host=" + server + " dstPort=" + dstPort)

    # We loop and accept source connections and spawn threads that handle proxy forwarding
    while 1:
        (client_socket, client_address) = server_socket.accept()

        # Current time the connection is initiated
        current_time = datetime.datetime.now().time()
        print("New connection: " + current_time.strftime("%Y-%m-%d %H:%M:%S") + ", from " + str(client_address))

        # Create a forwading socket that will forward information
        # obtained from the client to the destination through our server
        destination_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect to our destination server
        destination_socket.connect((server, int(dstPort)))

        # Start a thread that will handle the transfer of data between source and destination
        threading.Thread(target=connection_handler, args=(client_socket, destination_socket, log_option, n_bytes,
                                                          replace_option, option_one, option_two)).start()

