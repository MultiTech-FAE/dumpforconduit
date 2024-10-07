import subprocess
import os
import tarfile
import time
import platform
from datetime import datetime, timedelta
import threading
import sys
import shutil

def clear_screen():
    """Clear the screen based on the operating system."""
    os_type = platform.system()
    if os_type == "Windows":
        os.system("cls")
    else:
        os.system("clear")

def list_interfaces():
    """List available network interfaces using tcpdump."""
    print("\nListing available network interfaces...\n")
    try:
        result = subprocess.run(["tcpdump", "-D"], capture_output=True, text=True, check=True)
        interfaces = result.stdout.splitlines()
        for i, iface in enumerate(interfaces):
            print(f"{i + 1}. {iface}")
        print("\n")  # Add space after listing interfaces
        return interfaces
    except subprocess.CalledProcessError as e:
        print("\nError listing interfaces:", e, "\n")
        return []

def extract_interface_name(interface):
    """Extract the actual interface name from the output of tcpdump -D."""
    return interface.split('.')[1].split()[0]

def stop_tcpdump(process):
    """Stop the tcpdump process."""
    process.terminate()

def spinner():
    """A simple spinner to indicate that the program is running."""
    while True:
        for cursor in '|/-\\':
            yield cursor

def show_spinner(process):
    """Display a spinner while tcpdump is running."""
    spin = spinner()
    while process.poll() is None:
        sys.stdout.write(next(spin))  # Show the next spinner character
        sys.stdout.flush()  # Flush the buffer to show the character immediately
        sys.stdout.write('\b')  # Move the cursor back to overwrite the character
        time.sleep(0.1)  # Delay for smooth animation

def get_free_space(directory):
    """Return the total, used, and free space in the file system containing the given directory."""
    total, used, free = shutil.disk_usage(directory)
    return total, used, free

def get_space_from_user(free_space):
    """Ask the user if they want to use all available free space minus 15% or a custom amount."""
    guard_space = free_space * 0.15  # Reserve 15% of the free space
    available_space = free_space - guard_space
    print(f"\nThere is {free_space / (1024 * 1024):,.2f} MB of free space available.")
    print(f"To ensure system stability, 15% guard space ({guard_space / (1024 * 1024):,.2f} MB) will be reserved.")
    print(f"You can use up to {available_space / (1024 * 1024):,.2f} MB of space for capturing traffic.\n")

    use_full_space = input("Would you like to use the full available space minus 15%? (yes/no): ").strip().lower()
    
    if use_full_space == 'yes':
        return available_space / (1024 * 1024)  # Return available space in MB
    else:
        while True:
            try:
                user_space = float(input(f"How many MB would you like to use (max {available_space / (1024 * 1024):,.2f} MB): "))
                if user_space * 1024 * 1024 <= available_space:
                    return user_space
                else:
                    print(f"\nPlease enter a value less than or equal to {available_space / (1024 * 1024):,.2f} MB.\n")
            except ValueError:
                print("\nInvalid input. Please enter a number.\n")

def capture_pcap(interface, minutes, exclude_ip, directory, max_space_mb, port_filters, ip_filters):
    """Start tcpdump to capture packets on the chosen interface and stop when the pcap file reaches the specified size or time limit."""
    if not os.path.exists(directory):
        os.makedirs(directory)

    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_filename = f"{directory}/capture_{current_time}.pcap"
    max_file_size = min(20, max_space_mb)  # Ensure that max file size is no greater than 20 MB for each pcap

    print(f"\nStarting tcpdump on {interface}, saving to {pcap_filename}\n")
    print(f"tcpdump will run for {minutes} minute(s) or until the pcap file reaches {max_file_size} MB, whichever comes first.\n")
    
    tcpdump_command = ["tcpdump", "-i", interface, "-w", pcap_filename, "-C", str(int(max_file_size))]

    if exclude_ip:
        print(f"Excluding traffic from IP: {exclude_ip}\n")
        tcpdump_command += ["not", "host", exclude_ip]

    if port_filters:
        port_filter_string = " or ".join([f"port {port}" for port in port_filters])
        tcpdump_command += ["and", f"({port_filter_string})"]
        print(f"Including only traffic to and from ports: {', '.join(port_filters)}\n")

    if ip_filters:
        ip_filter_string = " or ".join([f"host {ip}" for ip in ip_filters])
        tcpdump_command += ["and", f"({ip_filter_string})"]
        print(f"Including only traffic to and from IP addresses: {', '.join(ip_filters)}\n")

    # Run tcpdump with the file size limit and optionally exclude the IP, and filter by port and IP address
    process = subprocess.Popen(
        tcpdump_command,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )

    # Create a thread to run the spinner while tcpdump is active
    spinner_thread = threading.Thread(target=show_spinner, args=(process,))
    spinner_thread.start()

    # Calculate the end time for the capture based on the user-defined duration
    end_time = datetime.now() + timedelta(minutes=minutes)

    # Wait for the specified number of minutes, but also monitor the process
    while datetime.now() < end_time and process.poll() is None:
        time.sleep(1)

    # Stop tcpdump if it hasn't already stopped (due to file size reaching limit)
    if process.poll() is None:
        print(f"\nStopping tcpdump after {minutes} minute(s).\n")
        stop_tcpdump(process)
    
    process.wait()  # Ensure process has completely terminated
    spinner_thread.join()  # Wait for the spinner thread to complete

    return pcap_filename

def archive_and_cleanup(pcap_filename, directory):
    """Archive the pcap file into a tarball and delete the original pcap file."""
    current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
    tar_filename = f"{directory}/capture_{current_time}.tar.gz"

    # Create tar.gz archive
    print(f"\nArchiving {pcap_filename} to {tar_filename}\n")
    with tarfile.open(tar_filename, "w:gz") as tar:
        tar.add(pcap_filename, arcname=os.path.basename(pcap_filename))

    # Delete the original pcap file
    print(f"Deleting original pcap file {pcap_filename}\n")
    os.remove(pcap_filename)

    return tar_filename

def warn_and_cleanup(directory):
    """Warn the user that existing files will be deleted and delete the files if the user confirms."""
    # Check for existing .pcap and .tar.gz files in the user-specified directory
    pcap_files = [f for f in os.listdir(directory) if f.endswith(".pcap")]
    tar_files = [f for f in os.listdir(directory) if f.endswith(".tar.gz")]

    if pcap_files or tar_files:
        print(f"\nWarning: The following files will be deleted from the directory '{directory}':\n")
        for f in pcap_files + tar_files:
            print(f"  - {f}")
        print("\n")  # Space after listing files
        user_input = input("Do you want to continue and delete these files? (yes/no): ")
        if user_input.lower() != "yes":
            print("\nExiting the program.\n")
            exit(0)

        # Delete the files
        for f in pcap_files + tar_files:
            file_path = os.path.join(directory, f)
            os.remove(file_path)
            print(f"Deleted: {file_path}\n")
    else:
        print(f"\nNo existing .pcap or .tar.gz files to delete in '{directory}'.\n")

def main():
    clear_screen()  # Clear the screen at the start of the program

    # Ask the user where to store the pcap and tar.gz files, with a default value of /var/volatile
    directory = input("Enter the directory to store the pcap and tar.gz files (default: /var/volatile): ").strip() or "/var/volatile"

    # Warn the user and delete any existing pcap/tar.gz files if they continue.
    warn_and_cleanup(directory)

    # Get free space available on the disk where the directory is located
    total_space, used_space, free_space = get_free_space(directory)

    # Ask the user how much space they want to use for capturing
    max_space_mb = get_space_from_user(free_space)

    interfaces = list_interfaces()
    if not interfaces:
        print("No interfaces found. Exiting.\n")
        return

    interface_choice = input("Enter the number of the interface you want to capture on: ")
    
    try:
        interface_index = int(interface_choice) - 1
        if interface_index < 0 or interface_index >= len(interfaces):
            print("\nInvalid interface choice.\n")
            return
    except ValueError:
        print("\nInvalid input. Please enter a number.\n")
        return

    interface = extract_interface_name(interfaces[interface_index])

    # Ask the user if they want to exclude traffic from their PC (SSH traffic)
    exclude_traffic = input("SSH traffic between your PC and this host is often considered 'noise' and you may not want to include it as part of the traffic capture. Do you want to exclude traffic from your PC? (yes/no): ").strip().lower() == 'yes'
    exclude_ip = None
    if exclude_traffic:
        exclude_ip = input("Enter the IP address of your computer to exclude from capture: ").strip()
        if not exclude_ip:
            print("\nInvalid IP address.\n")
            return

    # Ask the user if they want to filter traffic by ports
    filter_ports = input("Do you want to limit the traffic collection to certain IP ports? (yes/no): ").strip().lower() == 'yes'
    port_filters = None
    if filter_ports:
        ports_input = input("Enter the port(s) to include, separated by commas (e.g., 80,443): ").strip()
        port_filters = [port.strip() for port in ports_input.split(",") if port.strip().isdigit()]
        if not port_filters:
            print("\nNo valid ports entered. No port filters will be applied.\n")
    else:
        print("\nNo port filters will be put in place.\n")

    # Ask the user if they want to limit traffic to certain IP addresses
    filter_ips = input("Do you want to limit the traffic collection to certain IP addresses? (yes/no): ").strip().lower() == 'yes'
    ip_filters = None
    if filter_ips:
        ips_input = input("Enter the IP address(es) to include, separated by commas (e.g., 192.168.1.1,10.0.0.1): ").strip()
        ip_filters = [ip.strip() for ip in ips_input.split(",") if ip.strip()]
        if not ip_filters:
            print("\nNo valid IP addresses entered. No IP filters will be applied.\n")
    else:
        print("\nNo IP address filters will be put in place.\n")

    # Ask the user for the number of minutes to run tcpdump
    try:
        minutes = int(input("How many minutes would you like to run tcpdump? "))
        if minutes <= 0:
            print("\nPlease enter a valid number of minutes greater than zero.\n")
            return
    except ValueError:
        print("\nInvalid input. Please enter a number.\n")
        return

    # Run tcpdump for the specified time or until the file size reaches the user's limit
    pcap_filename = capture_pcap(interface, minutes, exclude_ip, directory, max_space_mb, port_filters, ip_filters)
    
    if pcap_filename:
        tar_filename = archive_and_cleanup(pcap_filename, directory)
        print(f"Capture saved as {tar_filename}\n")
        print("Note: Download the tar.gz file before rebooting, as files in /var/volatile will be erased on the next reboot.\n")
    else:
        print("No pcap file was created.\n")

if __name__ == "__main__":
    main()
