import socket
import sys
from datetime import datetime
import tkinter as tk
from tkinter import  messagebox, Label, Entry, Button, scrolledtext

def is_valid_port(port):
    try:
        port_num = int(port)
        if 1 <= port_num <= 65535:
            return True
        else:
            return False
    except ValueError:
        return False

def scan_ports():
    target_ip = target_ip_entry.get()
    start_port = start_port_entry.get()
    end_port = end_port_entry.get()

    if not is_valid_port(start_port) or not is_valid_port(end_port):
        messagebox.showerror("Invalid Port", "Port numbers should be positive integers between 1 and 65535.")
        return

    try:
        # Validate the input IP address
        socket.inet_aton(target_ip)
        start_port = int(start_port)
        end_port = int(end_port)

        # Clear previous results
        result_text.delete("1.0", tk.END)

        result_text.insert(tk.END, "=" * 50 + "\n")
        result_text.insert(tk.END, "Scanning target: " + target_ip + "\n")
        start_time = datetime.now()
        result_text.insert(tk.END, "Time started: " + str(start_time).split('.')[0] + "\n")
        result_text.insert(tk.END, "=" * 50 + "\n")

        open_tcp_ports = []

        for port in range(start_port, end_port + 1):
            # Check TCP ports
            tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_sock.settimeout(0.01)
            tcp_result = tcp_sock.connect_ex((target_ip, port))
            if tcp_result == 0:
                open_tcp_ports.append(port)
                service_name = socket.getservbyport(port, 'tcp')
                result_text.insert(tk.END, f'[+] Port {port}/TCP is open on {target_ip}. Service: {service_name}\n')

                if port == 21:
                    result_text.insert(tk.END, "   -> FTP (File Transfer Protocol) - Potential for FTP-based attacks.\n")
                    result_text.insert(tk.END, "   -> To prevent FTP-based attacks, consider using SFTP (SSH File Transfer Protocol) or FTPS (FTP Secure) which provide encryption and authentication.\n")
                    result_text.insert(tk.END, "   -> Implement strong password policies, use two-factor authentication, and restrict access to FTP services only from trusted IP addresses.\n")
                elif port == 22:
                    result_text.insert(tk.END, "   -> SSH (Secure Shell) - Potential for SSH brute force attacks.\n")
                    result_text.insert(tk.END, "   -> To prevent SSH brute force attacks, use key-based authentication instead of password authentication.\n")
                    result_text.insert(tk.END, "   -> Implement rate limiting to restrict the number of login attempts and consider using tools like fail2ban.\n")
                elif port == 23:
                    result_text.insert(tk.END, "   -> Telnet - Telnet protocol is insecure and prone to attacks.\n")
                    result_text.insert(tk.END, "   -> Replace Telnet with SSH for secure remote access.\n")
            tcp_sock.close()

        if not open_tcp_ports:
            result_text.insert(tk.END, f'No open ports found on {target_ip}.\n')

        end_time = datetime.now()
        duration = end_time - start_time
        result_text.insert(tk.END, "=" * 50 + "\n")
        result_text.insert(tk.END, "Scan completed.\n")
        result_text.insert(tk.END, "Time ended: " + str(end_time).split('.')[0] + "\n")
        result_text.insert(tk.END, "Duration of scan: " + str(duration.seconds) + " seconds\n")

    except socket.error:
        messagebox.showerror("Invalid IP", f"Invalid IP address format for {target_ip}. Please enter a valid IPv4 address.")
    except OverflowError:
        messagebox.showerror("Port Range Error", "Invalid port range. Please enter valid port numbers.")

def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit the port scanner?"):
        root.destroy()
        sys.exit()

# Create the GUI window
root = tk.Tk()
root.title("Port Scanner")
root.geometry("800x600")

# IP Address Label and Entry
ip_label = Label(root, text="Enter the IPv4 address to scan (e.g., 192.168.0.1):")
ip_label.pack(pady=5)
target_ip_entry = Entry(root)
target_ip_entry.pack(pady=5)

# Starting Port Label and Entry
start_port_label = Label(root, text="Enter the starting port number:")
start_port_label.pack(pady=5)
start_port_entry = Entry(root)
start_port_entry.pack(pady=5)

# Ending Port Label and Entry
end_port_label = Label(root, text="Enter the ending port number:")
end_port_label.pack(pady=5)
end_port_entry = Entry(root)
end_port_entry.pack(pady=5)

# Scan Button
scan_button = Button(root, text="Scan Ports", command=scan_ports)
scan_button.pack(pady=10)

# Result Text Area
result_text = scrolledtext.ScrolledText(root, wrap=tk.WORD)
result_text.pack(expand=True, fill=tk.BOTH)

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
