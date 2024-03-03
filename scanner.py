import socket
import sys
from datetime import datetime

def is_valid_port(port):
    try:
        port_num = int(port)
        if 1 <= port_num <= 65535:
            return True
        else:
            return False
    except ValueError:
        return False

def scan_ports(ip, start_port, end_port):
    # Print initial scan information
    print("=" * 50)
    print("Scanning target: " + ip)
    start_time = datetime.now()
    print("Time started: " + str(datetime.now()).split('.')[0])
    print("=" * 50)

    try:
        # Validate the port numbers
        if not is_valid_port(start_port) or not is_valid_port(end_port):
            raise ValueError("Invalid port numbers. Port numbers should be positive integers between 1 and 65535.")

        open_tcp_ports = []
        
        for port in range(start_port, end_port + 1):  # Iterate over the specified range of ports
            # Check TCP ports
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.settimeout(0.01)
            tcp_result = tcp_sock.connect_ex((ip, port))
            if tcp_result == 0:
                open_tcp_ports.append(port)
                service_name = socket.getservbyport(port, 'tcp')
                print(f'[+] Port {port}/TCP is open on {ip}. Service: {service_name}')

                # Additional information for specific well-known ports
                if port == 21:
                        print("   -> FTP (File Transfer Protocol) - Potential for FTP-based attacks.")
                        print("   -> To prevent FTP-based attacks, consider using SFTP (SSH File Transfer Protocol) or FTPS (FTP Secure) which provide encryption and authentication.")
                        print("   -> Implement strong password policies, use two-factor authentication, and restrict access to FTP services only from trusted IP addresses.")
                elif port == 22:
                        print("   -> SSH (Secure Shell) - Potential for SSH brute force attacks.")
                        print("   -> To prevent SSH brute force attacks, use key-based authentication instead of password authentication.")
                        print("   -> Implement rate limiting to restrict the number of login attempts and consider using tools like fail2ban.")
                elif port == 23:
                        print("   -> Telnet - Telnet protocol is insecure and prone to attacks.")
                        print("   -> Replace Telnet with SSH for secure remote access.")
            tcp_sock.close()

        if not open_tcp_ports:
            print(f'No open ports found on {ip}.')

        # Print scan completion information
        end_time = datetime.now()
        duration = end_time - start_time
        print("=" * 50)
        print("Scan completed.")
        print("Time ended: " + str(end_time).split('.')[0])  # Trimming microseconds
        print("Duration of scan: " + str(duration.seconds) + " seconds")

    except KeyboardInterrupt:
        print("\nExiting Scan.")
        sys.exit()
    except ValueError as ve:
        print(str(ve))
    except socket.gaierror:
        print(f"Could not find the host: {ip}. Check the provided IP address.")
        sys.exit()
    

if __name__ == "__main__":
    while True:
        target_ip = input("Enter the IPv4 address to scan (e.g., 192.168.0.1): ")
        try:
            socket.inet_aton(target_ip)  # Validate the input IP address
            start_port = int(input("Enter the starting port number: "))
            end_port = int(input("Enter the ending port number: "))
            scan_ports(target_ip, start_port, end_port)
            break  # Break the loop if the IP address is valid and scan completed
        except ValueError:
            print("Invalid input. Port numbers should be positive integers between 1 and 65535.")
        except socket.error:
            print(f"Invalid IP address format for {target_ip}. Please enter a valid IPv4 address.")
