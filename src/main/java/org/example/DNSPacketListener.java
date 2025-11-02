package org.example;

import org.pcap4j.core.*;
import org.pcap4j.packet.*;
import org.pcap4j.packet.namednumber.IpNumber;
import java.io.IOException;

public class DNSPacketListener {

    public static void main(String[] args) throws PcapNativeException, NotOpenException {
        // Select network interface
        PcapNetworkInterface nif = Pcaps.getDevByName("eth0"); // replace eth0 with your interface name

        if (nif == null) {
            System.out.println("No network interface found.");
            return;
        }

        int snapshotLength = 65536; // Capture full packet
        int readTimeout = 10; // ms

        PcapHandle handle = new PcapHandle.Builder(nif.getName())
                .snaplen(snapshotLength)
                .promiscuousMode(PcapNetworkInterface.PromiscuousMode.PROMISCUOUS)
                .timeoutMillis(readTimeout)
                .build();

        // Capture only DNS traffic (UDP port 53)
        String filter = "udp port 53";
        handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);

        PacketListener listener = new PacketListener() {
            @Override
            public void gotPacket(Packet packet) {
                try {
                    IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
                    if (ipV4Packet != null) {
                        String srcAddr = ipV4Packet.getHeader().getSrcAddr().getHostAddress();
                        String dstAddr = ipV4Packet.getHeader().getDstAddr().getHostAddress();
                        System.out.println("Source IP: " + srcAddr + " → Destination IP: " + dstAddr);
                    }

                    UdpPacket udpPacket = packet.get(UdpPacket.class);
                    if (udpPacket != null) {
                        byte[] payload = udpPacket.getPayload().getRawData();
                        System.out.println("Captured UDP Packet, Size: " + payload.length);
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        };

        System.out.println("Starting packet capture... Press Ctrl+C to stop.");
        try {
            handle.loop(-1, listener); // Capture indefinitely
        } catch (InterruptedException e) {
            System.out.println("Packet capture interrupted.");
            e.printStackTrace();
        } finally {
            handle.close();
        }


        handle.close();
    }
}

