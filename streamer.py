# do not import anything else from loss_socket besides LossyUDP
from lossy_socket import LossyUDP
# do not import anything else from socket except INADDR_ANY
from socket import INADDR_ANY
# yuyang wanted to use struct to make headers
import struct
# yuyang wanted to use concurrent futures for the background thread
from concurrent.futures import ThreadPoolExecutor
# yuyang wanted to use sleep and time for timeouts
from time import sleep, time
# yuyang wanted a lock because listener() and recv() share the same buffer
from threading import Lock
# yuyang wanted to use hashlib for md5 checksums
import hashlib


class Streamer:
    def __init__(self, dst_ip, dst_port,
                 src_ip=INADDR_ANY, src_port=0):
        """Default values listen on all network interfaces, chooses a random source port,
           and does not introduce any simulated packet loss."""
        self.socket = LossyUDP()
        self.socket.bind((src_ip, src_port))
        self.dst_ip = dst_ip
        self.dst_port = dst_port

        # yuyang wanted to keep track of the sequence number for sending
        self.sender_seq = 0

        # we also need to keep track of what sequence number we expect to receive next
        self.expected_seq = 0

        # create a dictionary to act as a buffer for out of order packets
        self.recv_buffer = {}

        # set a flag to tell the listener thread when to stop
        self.closed = False

        # yuyang wanted a lock so the listener thread and recv() don't fight over recv_buffer
        self.lock = Lock()

        # yuyang wanted a flag to track if we received a FIN from the other side
        self.fin_received = False

        # yuyang wanted a buffer to store sent packets in case we need to retransmit them
        # format: seq_num -> {'packet': bytes, 'time': float}
        self.send_buffer = {}

        # start the background listener thread using ThreadPoolExecutor
        self.executor = ThreadPoolExecutor(max_workers=2)
        self.executor.submit(self.listener)

        # yuyang wanted a separate thread to handle retransmissions without blocking send
        self.executor.submit(self.retransmission_handler)

    def listener(self) -> None:
        """This function runs in the background and constantly receives packets."""

        while not self.closed:
            try:
                packet, addr = self.socket.recvfrom()

                if self.closed:
                    break

                if len(packet) == 0:
                    continue

                # header is 21 bytes
                if len(packet) < 21:
                    continue

                # yuyang wanted to verify the checksum first
                received_hash = packet[0:16]
                body = packet[16:]
                calculated_hash = hashlib.md5(body).digest()

                if received_hash != calculated_hash:
                    print("DEBUG checksum mismatch dropping packet")
                    continue

                # unpack the header
                header = body[0:5]
                seq_num, msg_type = struct.unpack('!IB', header)

                # ACK packet type 1
                if msg_type == 1:
                    print("DEBUG received ACK seq " + str(seq_num))
                    with self.lock:
                        if seq_num in self.send_buffer:
                            del self.send_buffer[seq_num]
                    continue

                # FIN packet type 2
                if msg_type == 2:
                    print("DEBUG received FIN seq " + str(seq_num))
                    with self.lock:
                        self.fin_received = True

                    # send an ACK back for the FIN
                    ack_body = struct.pack('!IB', seq_num, 1)
                    ack_hash = hashlib.md5(ack_body).digest()
                    ack_packet = ack_hash + ack_body
                    self.socket.sendto(ack_packet, addr)
                    continue

                # DATA packet type 0
                data_payload = body[5:]
                print("DEBUG received DATA packet seq " + str(seq_num))

                # send ACK back immediately
                ack_body = struct.pack('!IB', seq_num, 1)
                ack_hash = hashlib.md5(ack_body).digest()
                ack_packet = ack_hash + ack_body
                self.socket.sendto(ack_packet, addr)

                with self.lock:
                    if seq_num < self.expected_seq:
                        continue
                    if seq_num in self.recv_buffer:
                        continue
                    self.recv_buffer[seq_num] = data_payload

            except Exception as e:
                print("listener died")
                print(e)

    def retransmission_handler(self) -> None:
        """This function runs in the background and checks for timeouts."""
        while not self.closed:
            sleep(0.01)

            current_time = time()

            # yuyang wanted to decide what to retransmit while holding the lock,
            # but do the actual send outside the lock so listener can keep running
            resend_list = []

            with self.lock:
                for seq, info in list(self.send_buffer.items()):
                    if current_time - info['time'] > 0.25:
                        resend_list.append((seq, info['packet']))
                        info['time'] = current_time  # reset timer now so we don't spam

            for seq, pkt in resend_list:
                print("DEBUG retransmitting packet seq " + str(seq))
                self.socket.sendto(pkt, (self.dst_ip, self.dst_port))

    def send(self, data_bytes: bytes) -> None:
        """Note that data_bytes can be larger than one packet."""

        length = len(data_bytes)
        header_size = 21
        limit = 1472 - header_size
        current = 0

        while current < length:
            end = current + limit
            if end > length:
                end = length

            chunk = data_bytes[current:end]

            # create the body
            body_header = struct.pack('!IB', self.sender_seq, 0)
            body = body_header + chunk

            # calculate hash
            body_hash = hashlib.md5(body).digest()
            packet = body_hash + body

            # yuyang wanted to store the packet in the buffer before sending
            with self.lock:
                self.send_buffer[self.sender_seq] = {
                    'packet': packet,
                    'time': time()
                }

            self.socket.sendto(packet, (self.dst_ip, self.dst_port))
            print("DEBUG sent packet seq " + str(self.sender_seq))

            self.sender_seq += 1
            current = end

    def recv(self) -> bytes:
        """Blocks (waits) if no data is ready to be read from the connection."""
        while True:
            with self.lock:
                if self.expected_seq in self.recv_buffer:
                    data = self.recv_buffer.pop(self.expected_seq)
                    print("DEBUG delivered packet from buffer seq " + str(self.expected_seq))
                    self.expected_seq += 1
                    return data

            if self.closed:
                return b''

            sleep(0.01)

    def close(self) -> None:
        """Cleans up. It should block (wait) until the Streamer is done with all
           the necessary ACKs and retransmissions"""

        print("DEBUG waiting for all packets to be ACKed")
        while True:
            with self.lock:
                if len(self.send_buffer) == 0:
                    break
            sleep(0.01)

        print("DEBUG starting close handshake")

        with self.lock:
            self.fin_received = False

        # yuyang wanted to use send_buffer strategy for FIN too,
        # IMPORTANT: put FIN in the buffer BEFORE sending so we don't miss the ACK
        fin_seq = self.sender_seq

        body = struct.pack('!IB', fin_seq, 2)
        fin_hash = hashlib.md5(body).digest()
        fin_packet = fin_hash + body

        with self.lock:
            self.send_buffer[fin_seq] = {
                'packet': fin_packet,
                'time': time()
            }

        self.socket.sendto(fin_packet, (self.dst_ip, self.dst_port))
        print("DEBUG sent FIN seq " + str(fin_seq))

        # wait for FIN to be acked (removed from buffer by listener)
        while True:
            with self.lock:
                if fin_seq not in self.send_buffer:
                    break
            sleep(0.01)

        self.sender_seq += 1

        # wait for FIN from the other side
        while True:
            with self.lock:
                if self.fin_received:
                    break
            sleep(0.01)

        print("DEBUG received FIN from other side")

        sleep(2)

        self.closed = True
        self.socket.stoprecv()
        self.executor.shutdown(wait=True)

        print("DEBUG Closing streamer connection")
        pass
