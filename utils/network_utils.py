# utils/network_utils.py
import socket
import json
import struct
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def send_message(sock: socket.socket, message_dict: dict):
    """Serializes, encodes, and sends a message dictionary with length prefix."""
    try:
        json_message = json.dumps(message_dict)
        encoded_message = json_message.encode('utf-8')
        message_length = len(encoded_message)
        # Pack length as 4-byte big-endian unsigned integer
        packed_length = struct.pack('>I', message_length)

        sock.sendall(packed_length)
        sock.sendall(encoded_message)
        logging.debug(f"Sent: {message_dict}")
        return True
    except socket.error as e:
        logging.error(f"Socket error during send: {e}")
        return False
    except Exception as e:
        logging.error(f"Error sending message: {e}")
        return False

def receive_message(sock: socket.socket) -> dict | None:
    """Receives a length-prefixed message, decodes, and deserializes it."""
    try:
        # Receive the 4-byte length prefix
        packed_length = sock.recv(4)
        if not packed_length:
            logging.info("Connection closed by peer (no length received).")
            return None # Connection closed
        if len(packed_length) < 4:
            logging.warning("Incomplete length received. Connection likely closing.")
            return None # Incomplete data

        message_length = struct.unpack('>I', packed_length)[0]
        logging.debug(f"Expecting message length: {message_length}")

        # Receive the actual message data based on the length
        message_bytes = b''
        bytes_recd = 0
        while bytes_recd < message_length:
            # Read in chunks to avoid blocking indefinitely on large messages
            # or issues with network fragmentation
            chunk_size = min(message_length - bytes_recd, 2048)
            chunk = sock.recv(chunk_size)
            if not chunk:
                logging.error("Socket connection broken while receiving message body.")
                raise ConnectionError("Socket connection broken")
            message_bytes += chunk
            bytes_recd += len(chunk)

        decoded_message = message_bytes.decode('utf-8')
        message_dict = json.loads(decoded_message)
        logging.debug(f"Received: {message_dict}")
        return message_dict

    except struct.error as e:
        logging.error(f"Struct unpacking error: {e}. Malformed length prefix?")
        return None
    except socket.error as e:
        # Check for specific errors if needed, e.g., ConnectionResetError
        logging.error(f"Socket error during receive: {e}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"JSON decoding error: {e}. Received malformed data.")
        # Log the problematic data if possible and safe
        # logging.debug(f"Malformed data received: {message_bytes.hex() if 'message_bytes' in locals() else 'N/A'}")
        return None
    except ConnectionError as e:
        logging.error(f"Connection error: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error receiving message: {e}")
        return None