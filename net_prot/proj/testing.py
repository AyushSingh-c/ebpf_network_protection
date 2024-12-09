

def reduce_checksum(checksum):
    while checksum >> 16:
        # Add carry if any
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return checksum

def one_comple_checksum(checksum):
    return (~checksum) & 0xFFFF

def calculate_checksum(bytes):
    """
    Calculate the checksum for the given bytes.
    """
    checksum = 0
    # Process each 16-bit word
    for i in range(0, len(bytes), 2):
        word = (bytes[i] << 8) + (bytes[i + 1])
        checksum += word
    checksum = reduce_checksum(checksum)
    # One's complement
    checksum = one_comple_checksum(checksum)
    return checksum

def update_checksum(old_checksum, old_value, new_value):
    """
    Update the checksum incrementally.
    """
    # Calculate the difference
    diff = reduce_checksum(one_comple_checksum(calculate_checksum(old_value)) + (calculate_checksum(new_value)))
    print("Testing Difference:", hex(diff))
    # Update the checksum
    new_checksum = reduce_checksum(old_checksum + diff)
    return new_checksum

def update_checksum_once_more(old_checksum, old_value, new_value):
    """
    Update the checksum incrementally.
    """
    # Calculate the difference
    old_value = [0xa9, 0xfe, 0x04, 0x02]
    new_value = [0xc0, 0xa8, 0x01, 0x01]
    diff = reduce_checksum(calculate_checksum(old_value) + one_comple_checksum(calculate_checksum(new_value)))
    # diff = 0xaa16
    print("Testing Difference:", hex(diff))
    # Update the checksum
    new_checksum = one_comple_checksum(reduce_checksum(one_comple_checksum(old_checksum) + diff))
    return new_checksum


def testing_tcp_cksum():
    # initial_checksum = 0x11fc
    initial_checksum = 0xa21a
    diff = 0xaa16
    old_value = [0x02, 0x04, 0xfe, 0xa9]
    new_value = [0x01, 0x01, 0xa8, 0xc0]
    # final_checksum = 0x68e8
    final_checksum = 0xf803

    print("Initial checksum:", hex(initial_checksum))
    print("Difference:", hex(diff))
    print("Old value:", (old_value))
    print("New value:", (new_value))
    print("Test checksum:", hex(update_checksum_once_more(initial_checksum, old_value, new_value)))
    print("Final checksum:", hex(final_checksum))
    return

import socket
import struct

SOCKET_PATH = "/tmp/net_prot_socket"

def send_data(isolation_setup):
    # Create a Unix domain socket
    client_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    try:
        # Connect to the server
        client_socket.connect(SOCKET_PATH)

        # Pack the data into the format expected by the C++ struct
        data = struct.pack('?', isolation_setup)

        # Send the data
        client_socket.sendall(data)
        print(f"Sent isolation_setup: {isolation_setup}")

    except socket.error as e:
        print(f"Socket error: {e}")

    finally:
        # Clean up
        client_socket.close()

if __name__ == "__main__":
    send_data(False)