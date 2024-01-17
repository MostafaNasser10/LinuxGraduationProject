#!/bin/bash

# Bash Script to Analyze Network Traffic
# Function to extract information from the pcap file
function analyze_traffic() {
    # Use tshark or similar commands for packet analysis.
    # extract IP addresses, and generate summary statistics.
    tshark -r $1 -Y "tls.handshake.type == 1 or tls.handshake.type == 2 or tls.handshake.type == 3 or http" > Output.txt

    declare -i TOTAL_PACKETS=`cat Output.txt |wc -l`
    declare -i HTTP_PACKETS=`cat Output.txt |grep -c "HTTP"`
    declare -i TLS_PACKETS=`cat Output.txt |grep -c "TLS\|QUIC"`

    # Output analysis summary
    echo "___________________________________________________________________"
    echo "----- Network Traffic Analysis Report -----"
    echo "___________________________________________________________________"
    # Provide summary information based on your analysis
    # Hints: Total packets, protocols, top source, and destination IP addresses.
    echo "1. Total Packets: [$TOTAL_PACKETS]"
    echo ""
    echo "___________________________________________________________________"
    echo "2. Protocols:"
    echo "   - HTTP: [$HTTP_PACKETS] packets"
    echo "   - HTTPS/TLS: [$TLS_PACKETS] packets"
    echo ""
    echo "___________________________________________________________________"
    echo "3. Top 5 Source IP Addresses:"
    # Provide the top source IP addresses
    tshark -r "$1" -Y "tls.handshake.type == 1 or tls.handshake.type == 2 or tls.handshake.type == 3 or http" -T fields -e ip.src | sort -n  | uniq -c > sortSrc.txt
    sort -rn sortSrc.txt | head -5 | while IFS= read -r line; do
        printf "%s \t :  %d\tTimes\n" "${line##* }" "${line% *}"
    done 
    
    echo ""
    echo ""
    echo "___________________________________________________________________"
    echo "4. Top 5 Destination IP Addresses:"
    # Provide the top destination IP addresses
    tshark -r "$1" -Y "tls.handshake.type == 1 or tls.handshake.type == 2 or tls.handshake.type == 3 or http" -T fields -e ip.dst | sort -n  | uniq -c > sortDst.txt
    sort -rn sortDst.txt | head -5 | while IFS= read -r line; do
        printf "%s \t :  %d\tTimes\n" "${line##* }" "${line% *}"
    done 

    echo ""
    
    echo "----- End of Report -----"
    declare Src=""
    declare Dst=""
    Src="$(sort -rn sortSrc.txt | head -5 | while IFS= read -r line; do
        printf "%s\t: %d\tTimes\n" "${line##* }" "${line% *}"
    done )"

    Dst="$(sort -rn sortDst.txt | head -5 | while IFS= read -r line; do
        printf "%s\t: %d\tTimes\n" "${line##* }" "${line% *}"
    done )"
    zenity --info --text="- Total Packets:  $TOTAL_PACKETS \n\nProtocols:-\n- HTTP:  $HTTP_PACKETS packets\n- TLS:  $TLS_PACKETS packets\n\nTop 5 Source IP Addresses:\n$Src\n\nTop 5 Dest IP Addresses:\n$Dst"
}

# Input: Path to the Wireshark pcap file
pcap_file=`zenity --file-selection --title="Select a File"`

case $? in
         0)
                echo "\"$pcap_file\" selected."
                # Run the analysis function
                analyze_traffic "$pcap_file"
                ;;
         1)
                echo "No file selected."
                zenity --error --text="No file Chosen"
                ;;
esac