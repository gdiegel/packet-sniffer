package io.github.gdiegel.packetsniffer;

import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.InterfaceAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.pcap4j.core.PcapNetworkInterface.PromiscuousMode.PROMISCUOUS;

public class Main {

    private static final Logger LOG = LoggerFactory.getLogger(Main.class);

    public static void main(String[] args) throws SocketException, PcapNativeException, NotOpenException {
        final String interfaceName = args.length > 0 ? args[0] : "en0";
        final NetworkInterface networkInterface = NetworkInterface.getByName(interfaceName);
        printInfo(networkInterface);
        final PcapNetworkInterface pcapNetworkInterface = Pcaps.getDevByName(interfaceName);
        LOG.debug("Link layer addresses: {}", pcapNetworkInterface.getLinkLayerAddresses());
        try (final PcapHandle handle = pcapNetworkInterface.openLive(65536, PROMISCUOUS, 10)) {
            LOG.debug(String.valueOf(handle.listDatalinks()));

            final PacketListener listener = packet ->
                LOG.info("Packet at {}:\n{}", handle.getTimestamp(), packet.getPayload());

            try {
                final ExecutorService executorService = Executors.newSingleThreadExecutor();
                handle.loop(-1, listener, executorService);
                executorService.shutdown();
            } catch (InterruptedException e) {
                LOG.error("Interrupted", e);
            }

            final PcapStat pcapStat = handle.getStats();
            LOG.debug("ps_recv: " + pcapStat.getNumPacketsReceived());
            LOG.debug("ps_drop: " + pcapStat.getNumPacketsDropped());
            LOG.debug("ps_ifdrop: " + pcapStat.getNumPacketsDroppedByIf());
        }
    }

    private static void printInfo(NetworkInterface networkInterface) throws SocketException {
        LOG.debug("Name: {}", networkInterface.getName());
        LOG.debug("Display name: {}", networkInterface.getDisplayName());
        LOG.debug("Interface addresses:");
        for (InterfaceAddress interfaceAddress : networkInterface.getInterfaceAddresses()) {
            LOG.debug("  Interface address: {}", interfaceAddress.getAddress());
            LOG.debug("  Broadcast address: {}", interfaceAddress.getBroadcast());
            LOG.debug("  Network prefix length: {}", interfaceAddress.getNetworkPrefixLength());
        }
        LOG.debug("Hardware address: {}", networkInterface.getHardwareAddress());
        LOG.debug("Supports multicast: {}", networkInterface.supportsMulticast());
        LOG.debug("Is point-to-point: {}", networkInterface.isPointToPoint());
        LOG.debug("Up: {}", networkInterface.isUp());
        networkInterface.subInterfaces().forEach(subInterface -> LOG.debug("Sub interface: {}", subInterface));
    }
}
