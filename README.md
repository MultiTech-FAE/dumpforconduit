# dumpforconduit

A Python script that collects packet data through a guided interface.

Sometimes a customer is experiencing high network traffic on a particular interface (like a cell connection) and they don't know why. The most obvious tool to investigate the situation is TCPDUMP, but it is not trivial to set up a collection session - the command line can be tedious to enter and prone to error, especially if there are multiple filters in place.

dumpforconduit guides the user through the process by asking questions and requiring input to build the command line. It then executes the command and returns a pcap file that can be analyzed by something like Wireshark. There are protections built in to prevent the pcap file from filling up the available disk space. The pcap is tar'd after completion to make it smaller, and the files are placed in /var/volatile by default so that they will be deleted on next boot, if the user doesn't delete them.

There is a manual with images and step-by-step instructions that would be appropriate to give to a customer.
