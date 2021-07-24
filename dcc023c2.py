import sys, os
import binascii
import threading
import socket

MAX_DATA = 512 
DATA = '7f'
DLE = '1b'
EOF = 'cd'
ACK = '80'     
SOF = 'cc'

#Message should not have byte stuffing to calculate the sum 
original_data = b'' 

class Data:
    def __init__(self, id = 1, data = '', flags = 127, confirmed = False):
        self.id = id
        self.data = data
        self.flags = flags
        self.confirmed = confirmed

    def prepare(self):        
        self.id = 1 if self.id == 0 else 0
        self.confirmed = False
    
    def encode(self, data):
        return binascii.hexlify(data)
    
    def decode(self, data):
        self.data = binascii.unhexlify(data)

    def get_frame(self):
        id = self.format_number(self.id, False)
        data = self.encode(self.data)
        flags = self.format_number(self.flags, False)
        checksum = self.format_number(self.check_sum())        
        header = (id + flags + checksum).encode()
        return header + data + EOF.encode() 

    @staticmethod
    def format_number(number, has_two_bytes = True):
        pattern = '{:04x}' if has_two_bytes else '{:02x}'
        return pattern.format(number)

    def check_sum(self):        
        data = SOF 
        data += self.format_number(self.id, False)
        data += self.format_number(self.flags, False)
        data += self.format_number(0)
        data = binascii.unhexlify(data.encode()) + original_data

        size_default = 16
        checksum = 0
        pointer = 0
        size = len(data)        

        while size > 1:
            checksum += int(str('%02x' % (data[pointer],)) + str('%02x' % (data[pointer + 1],)), size_default)
            pointer += 2
            size -= 2            
        if size: checksum += data[pointer]

        checksum = (checksum >> size_default) + (checksum & 0xffff)
        checksum += (checksum >> size_default)

        return (~checksum) & 0xFFFF

sent_data = Data(id = 0)
received_data = Data()

def send_thread(connection, INPUT):
    send_thread = threading.Thread(target=send, args=(connection, INPUT))
    send_thread.start()

def receive_thread(connection, OUTPUT):
    receive_thread = threading.Thread(target=receive, args=(connection, OUTPUT))
    receive_thread.start()

def remove_file(file):    
    if os.path.exists(file):
        os.remove(file)

def connect(IP, PORT):
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    connection.connect((IP, PORT))
    return connection

def handle_timeout():
    global timeout
    timeout = True

def boot_server():
    #Getting server informations
    IP = '127.0.0.1'
    try:        
        PORT = int(sys.argv[2])
        INPUT = sys.argv[3]
        OUTPUT = sys.argv[4]
    except:
        print('Boot server: \n <PORT> <INPUT> <OUTPUT> \n Example: 5442 in.txt out.txt')
        exit(2)

    #Creating socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error:
        print("Error create socket")
        exit(2)

    #Creating server    
    try:
        s.bind((IP, PORT))
        s.listen(1)
        print('Server created on the port ' + str(PORT))
        connection, addr = s.accept()
    except KeyboardInterrupt:
        s.close()
        sys.exit(0)  

    #Threads that will be sent and received in parallel
    send_thread(connection, INPUT)
    receive_thread(connection, OUTPUT)    

def boot_client():
    #Getting client informations
    try:
        complete_address = sys.argv[2].split(':')
        IP = complete_address[0]
        PORT = int(complete_address[1])
        INPUT = sys.argv[3]
        OUTPUT = sys.argv[4]
    except:
        print('Boot client: \n <IP> <PORT> <INPUT> <OUTPUT> \n Example: 127.0.0.1:5442 in.txt out.txt')
        exit(2)

    #Removing output file 
    remove_file(OUTPUT)

    #Creating TCP connection
    connection = connect(IP, PORT)    

    #Threads that will be sent and received in parallel
    send_thread(connection, INPUT)
    receive_thread(connection, OUTPUT)

def send(connection, input):    
    counter = MAX_DATA
    original_message = b''
    message = b''

    with open(input, 'rb') as file:
        line = file.read(1)
        
        while (counter > 0 and line):
            encode_message = sent_data.encode(line)            
            
            #It's necessary to do the byte stuffing if it's DLE or EOF 
            if encode_message == DLE or encode_message == EOF: 
                message += DLE
                counter -= 1
            
            message += encode_message
            original_message += line
            counter -= 1 
            if counter > 0:
                line = file.read(1) 

        sent_data.data = message
        global original_data
        original_data = original_message
        print('Data sent from: ' + input + ' file')

        connection.send(SOF.encode())
        connection.send(sent_data.get_frame())

        #Checking timeout
        global timeout
        timeout = False  
        timer = threading.Timer(1, handle_timeout)
        timer.start()
        while True:
            if timeout:
                print('Timeout error: ACK was not received')
                break

            if sent_data.confirmed:
                line = file.read(MAX_DATA)
                sent_data.prepare()
                break

def receive(connection, output):    
    id = 1 
    data = ''

    while True:
        #Receiving a SOF
        sof = connection.recv(2)
        if sof.decode() != SOF:
            continue
        
        id = connection.recv(2)
        received_data.id = int(id.decode(), base=16)

        flags = connection.recv(2)
        received_data.flags = int(flags.decode(), base=16)

        received_checksum = connection.recv(4)
        received_checksum = int(received_checksum.decode(), base=16)

        try:
            if (flags == DATA):
                aux = connection.recv(2)
                data += aux 
                while (aux):
                    if(aux == DLE):
                        aux = connection.recv(2)
                        data += aux
                        aux = connection.recv(2)
                        continue

                    if(aux.decode() == EOF):
                        break               
                    
                    aux = connection.recv(2)
                    data += aux
                    aux = connection.recv(2)

                received_data.decode(data)

        except binascii.Error or UnicodeDecodeError:
            print('Conversion error')
            continue

        #Checking checksum
        if received_data.check_sum() != received_checksum:
            print('Checksum error')
            continue

        # 128 = ACK em decimal
        if received_data.flags == 128:
            if received_data.id == sent_data.id:
                print('ACK received')
                sent_data.confirmed = True
        else:
            # Se não for ACK, então é dados
            expected_id = 1 if id == 0 else 0
            if received_data.id != expected_id:
                print('Retransmitting data and resending ACK')
                received_data.data = b''
                received_data.flags = 128
                connection.send(SOF.encode())
                connection.send(received_data.get_frame())
                continue

            with open(output, 'ab') as file:
                file.write(original_data)
                print('Data received in {} file\nSending ACK'.format(output))
                received_data.data = b''
                received_data.flags = 128
                id = received_data.id

                connection.send(SOF.encode())
                connection.send(received_data.get_frame())

def error():
    print('Boot system: \n Server <PORT> <INPUT> <OUTPUT> \n Example: -s 5442 in.txt out.txt \n\n Client <IP> <PORT> <INPUT> <OUTPUT> \n Example: -c 127.0.0.1:5442 in.txt out.txt')
    exit(2)

def main():
    try:
        action = sys.argv[1]
    except:
        error()
        
    if action == '-s':
        boot_server()
    elif action == '-c':
        boot_client()    
    else:
        error()

if __name__ == '__main__':
    main()