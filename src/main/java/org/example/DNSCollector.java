package org.example;

import org.pcap4j.core.*;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.UdpPacket;
import org.xbill.DNS.Message;
import org.xbill.DNS.Record;
import org.xbill.DNS.Type;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.sql.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ThreadLocalRandom;

/**
 * DNS Collector - supports two modes:
 *  - simulate : generate a sample dataset and write to sqlite + CSV
 *  - live     : capture live UDP/53 traffic, parse DNS records, write to sqlite
 *
 * Usage:
 *  mvn package
 *  # simulate mode (no root) - generates sample data
 *  java -cp target/dns-collector-1.0.0.jar edu.project.dnsids.DnsCollector simulate
 *
 *  # live mode (may require root/admin)
 *  sudo java -cp target/dns-collector-1.0.0.jar edu.project.dnsids.DnsCollector live
 */
public class DNSCollector {
    private static final String DB_PATH = "./dnsids.db";
    private static final String QUERY_TABLE =
            "CREATE TABLE IF NOT EXISTS queries (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                    "ts REAL, client_ip TEXT, client_port INTEGER, qname TEXT, qtype TEXT, response_code INTEGER, answer_count INTEGER, raw_len INTEGER" +
                    ");";
    private static final String ALERTS_TABLE =
            "CREATE TABLE IF NOT EXISTS alerts (" +
                    "id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, client_ip TEXT, reason TEXT, detail TEXT" +
                    ");";

    // Simple noise filters (can expand)
    private static boolean isNoisyQuery(String qname, String clientIp) {
        if (qname == null) return true;
        String s = qname.trim();
        if (s.length() == 0) return true;
        // drop single-character or very short names like 'a' or '.' that are likely noise
        if (s.length() < 3) return true;
        // drop localhost / internal names
        if (s.contains("localhost") || s.endsWith(".local") || s.startsWith("127.") || clientIp.startsWith("127.")) return true;
        return false;
    }

    public static void main(String[] args) throws Exception {
        String mode = (args.length >= 1) ? args[0].trim().toLowerCase() : "simulate";
        initDb();

        System.out.println("DB initialized at " + DB_PATH);
        if ("simulate".equals(mode)) {
            System.out.println("Running in SIMULATE mode: generating sample dataset");
            generateSampleDataset(500); // default 500 sample queries
            exportCsv("./queries_export.csv");
            System.out.println("Sample dataset generated and exported to queries_export.csv");
        } else if ("live".equals(mode)) {
            System.out.println("Running in LIVE capture mode. You may need admin privileges to capture packets.");
            runLiveCapture();
        } else {
            System.err.println("Unknown mode. Use 'simulate' or 'live'.");
        }
    }

    // Initialize DB and create tables if needed
    private static void initDb() {
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH)) {
            try (Statement s = c.createStatement()) {
                s.execute(QUERY_TABLE);
                s.execute(ALERTS_TABLE);
            }
        } catch (SQLException e) {
            e.printStackTrace();
            throw new RuntimeException("DB init failed");
        }
    }

    // Insert a query row (thread-safe via per-call connection)
    private static void insertQueryRow(double ts, String clientIp, int clientPort, String qname, String qtype, int rcode, int answerCount, int rawLen) {
        // Apply noise filters before inserting
        if (isNoisyQuery(qname, clientIp)) return;

        String sql = "INSERT INTO queries (ts, client_ip, client_port, qname, qtype, response_code, answer_count, raw_len) VALUES (?,?,?,?,?,?,?,?)";
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
             PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setDouble(1, ts);
            ps.setString(2, clientIp);
            ps.setInt(3, clientPort);
            ps.setString(4, qname);
            ps.setString(5, qtype);
            ps.setInt(6, rcode);
            ps.setInt(7, answerCount);
            ps.setInt(8, rawLen);
            ps.executeUpdate();
            System.out.println("Inserted query: " + qname + " from " + clientIp);
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Live capture loop using Pcap4J
    private static void runLiveCapture() throws PcapNativeException, NotOpenException {
        List<PcapNetworkInterface> all = Pcaps.findAllDevs();
        if (all == null || all.isEmpty()) {
            System.err.println("No interfaces found. Exiting.");
            return;
        }
        // Choose first non-loopback
        PcapNetworkInterface nif = null;
        for (PcapNetworkInterface n : all) {
            if (!n.isLoopBack()) {
                nif = n;
                break;
            }
        }
        if (nif == null) nif = all.get(0);

        System.out.println("Selected interface: " + nif.getName() + " - " + nif.getDescription());
        int snapLen = 65536;
        int timeout = 10;
        final PcapHandle handle = nif.openLive(snapLen, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, timeout);
        String filter = "udp and port 53";
        try {
            handle.setFilter(filter, BpfProgram.BpfCompileMode.OPTIMIZE);
        } catch (NotOpenException e) {
            e.printStackTrace();
        }
        PacketListener listener = packet -> {
            try {
                if (!packet.contains(UdpPacket.class)) return;
                UdpPacket udp = packet.get(UdpPacket.class);
                byte[] payload = udp.getPayload() != null ? udp.getPayload().getRawData() : null;
                if (payload == null || payload.length == 0) return;

                try {
                    Message dns = new Message(payload);
                    Record[] questions = dns.getSectionArray(org.xbill.DNS.Section.QUESTION);
                    String qname = questions.length > 0 ? questions[0].getName().toString() : "<unknown>";
                    int qtype = (questions.length > 0) ? questions[0].getType() : Type.value("UNKNOWN");

                    int rcode = dns.getRcode();
                    int answerCount = dns.getSectionArray(org.xbill.DNS.Section.ANSWER).length;

                    // ✅ Corrected source IP extraction
                    IpV4Packet ipV4 = packet.get(IpV4Packet.class);
                    String srcAddr = "<unknown>";
                    if (ipV4 != null) {
                        srcAddr = ipV4.getHeader().getSrcAddr().getHostAddress();
                    } else {
                        IpV6Packet ipV6 = packet.get(IpV6Packet.class);
                        if (ipV6 != null) {
                            srcAddr = ipV6.getHeader().getSrcAddr().getHostAddress();
                        }
                    }

                    int srcPort = udp.getHeader().getSrcPort().valueAsInt();
                    insertQueryRow(Instant.now().getEpochSecond(), srcAddr, srcPort, qname, Type.string(qtype), rcode, answerCount, payload.length);
                    System.out.println("Inserted: " + srcAddr + " -> " + qname + " type=" + Type.string(qtype));
                } catch (Exception e) {
                    // parse failure - ignore
                }
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        };


        try {
            System.out.println("Starting capture loop. Press Ctrl+C to stop.");
            handle.loop(-1, listener);
        } catch (InterruptedException e) {
            System.out.println("Interrupted, closing handle.");
        } finally {
            handle.close();
        }
    }

    // Generate realistic-ish synthetic DNS queries for testing
    private static void generateSampleDataset(int n) {
        String[] domains = new String[] {
                "example.com.", "google.com.", "bing.com.", "malicious.example.", "random-domain.net."
        };
        String[] types = new String[] {"A","AAAA","TXT","MX","CNAME"};
        for (int i = 0; i < n; i++) {
            double ts = Instant.now().getEpochSecond() - ThreadLocalRandom.current().nextInt(0, 3600);
            String ip = "192.168.1." + ThreadLocalRandom.current().nextInt(2, 250);
            int port = ThreadLocalRandom.current().nextInt(1024, 65535);
            // sometimes generate long/entropy labels to emulate exfil
            String qname;
            if (ThreadLocalRandom.current().nextDouble() < 0.05) {
                // high-entropy label
                qname = randomBase32(40) + "." + domains[ThreadLocalRandom.current().nextInt(domains.length)];
            } else if (ThreadLocalRandom.current().nextDouble() < 0.05) {
                // long label
                qname = randomAlpha(60) + "." + domains[ThreadLocalRandom.current().nextInt(domains.length)];
            } else {
                qname = "www." + domains[ThreadLocalRandom.current().nextInt(domains.length)];
            }
            String qtype = types[ThreadLocalRandom.current().nextInt(types.length)];
            int rcode = (ThreadLocalRandom.current().nextDouble() < 0.05) ? 3 : 0; // 3 -> NXDOMAIN occasionally
            int answerCount = (rcode == 0) ? ThreadLocalRandom.current().nextInt(0,3) : 0;
            int rawLen = ThreadLocalRandom.current().nextInt(50, 400);
            insertQueryRow(ts, ip, port, qname, qtype, rcode, answerCount, rawLen);
        }
    }

    private static String randomAlpha(int len) {
        StringBuilder sb = new StringBuilder(len);
        String chars = "abcdefghijklmnopqrstuvwxyz";
        for (int i = 0; i < len; i++) sb.append(chars.charAt(ThreadLocalRandom.current().nextInt(chars.length())));
        return sb.toString();
    }

    private static String randomBase32(int len) {
        StringBuilder sb = new StringBuilder(len);
        String chars = "abcdefghijklmnopqrstuvwxyz23456";
        for (int i = 0; i < len; i++) sb.append(chars.charAt(ThreadLocalRandom.current().nextInt(chars.length())));
        return sb.toString();
    }

    // Export queries table to CSV for offline analysis / feature extraction
    private static void exportCsv(String outPath) {
        String q = "SELECT ts, client_ip, client_port, qname, qtype, response_code, answer_count, raw_len FROM queries ORDER BY ts ASC";
        try (Connection c = DriverManager.getConnection("jdbc:sqlite:" + DB_PATH);
             PreparedStatement ps = c.prepareStatement(q);
             ResultSet rs = ps.executeQuery();
             PrintWriter pw = new PrintWriter(new FileWriter(outPath))) {

            pw.println("ts,client_ip,client_port,qname,qtype,response_code,answer_count,raw_len");
            while (rs.next()) {
                pw.printf(Locale.ROOT, "%.0f,%s,%d,%s,%s,%d,%d,%d%n",
                        rs.getDouble("ts"),
                        sanitizeCsv(rs.getString("client_ip")),
                        rs.getInt("client_port"),
                        sanitizeCsv(rs.getString("qname")),
                        sanitizeCsv(rs.getString("qtype")),
                        rs.getInt("response_code"),
                        rs.getInt("answer_count"),
                        rs.getInt("raw_len"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static String sanitizeCsv(String s) {
        if (s == null) return "";
        return s.replace("\"", "\"\"");
    }
}
