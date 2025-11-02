package org.example;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

public class ListInterfaces {
    public static void main(String[] args) throws PcapNativeException {
        for (PcapNetworkInterface dev : Pcaps.findAllDevs()) {
            System.out.println(dev.getName() + " : " + dev.getDescription());
        }
    }
}
