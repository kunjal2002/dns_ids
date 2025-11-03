package org.example;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

/**
 * Feature Extraction Module for DNS Anomaly Detection System
 * 
 * Computes the following features:
 * 1. Query rate per client (queries per minute/second)
 * 2. Average and maximum subdomain length
 * 3. Entropy of subdomain strings (Shannon entropy)
 * 4. Frequency of NXDOMAIN responses
 */
public class DNSFeatureExtractor {
    
    // Inner class to hold per-client statistics
    static class ClientFeatures {
        String clientIp;
        int totalQueries;
        double firstTimestamp;
        double lastTimestamp;
        List<Integer> subdomainLengths;
        List<String> subdomains;
        int nxdomainCount;
        
        ClientFeatures(String clientIp) {
            this.clientIp = clientIp;
            this.subdomainLengths = new ArrayList<>();
            this.subdomains = new ArrayList<>();
            this.totalQueries = 0;
            this.firstTimestamp = Double.MAX_VALUE;
            this.lastTimestamp = Double.MIN_VALUE;
            this.nxdomainCount = 0;
        }
    }
    
    /**
     * Extract subdomain from a fully qualified domain name
     * Example: "www.example.com." -> "www"
     * Example: "subdomain.example.com." -> "subdomain"
     * Example: "very.long.subdomain.example.com." -> "very.long.subdomain"
     */
    private static String extractSubdomain(String qname) {
        if (qname == null || qname.isEmpty()) {
            return "";
        }
        
        // Remove trailing dot if present
        String domain = qname.endsWith(".") ? qname.substring(0, qname.length() - 1) : qname;
        
        // Split by dots
        String[] parts = domain.split("\\.");
        
        if (parts.length <= 1) {
            return "";
        }
        
        // Extract everything before the last two parts (assuming TLD and base domain)
        // For "sub.example.com", subdomain would be "sub"
        // For "a.b.c.example.com", subdomain would be "a.b.c"
        if (parts.length == 2) {
            return parts[0];
        } else {
            // Join all parts except the last two (TLD and base domain)
            StringBuilder subdomain = new StringBuilder();
            for (int i = 0; i < parts.length - 2; i++) {
                if (i > 0) subdomain.append(".");
                subdomain.append(parts[i]);
            }
            return subdomain.toString();
        }
    }
    
    /**
     * Calculate Shannon entropy of a string
     * Entropy measures the randomness/unpredictability of characters
     * Higher entropy = more random = potentially suspicious (data exfiltration)
     */
    private static double calculateEntropy(String str) {
        if (str == null || str.isEmpty()) {
            return 0.0;
        }
        
        Map<Character, Integer> charCounts = new HashMap<>();
        int length = str.length();
        
        // Count frequency of each character
        for (char c : str.toCharArray()) {
            charCounts.put(c, charCounts.getOrDefault(c, 0) + 1);
        }
        
        // Calculate entropy: H(X) = -Σ p(x) * log2(p(x))
        double entropy = 0.0;
        for (int count : charCounts.values()) {
            double probability = (double) count / length;
            entropy -= probability * (Math.log(probability) / Math.log(2));
        }
        
        return entropy;
    }
    
    /**
     * Parse CSV file and extract features
     */
    public Map<String, ClientFeatures> extractFeaturesFromCsv(String csvFilePath) throws IOException {
        Map<String, ClientFeatures> clientStats = new HashMap<>();
        
        try (BufferedReader br = new BufferedReader(new FileReader(csvFilePath))) {
            String line = br.readLine(); // Skip header
            if (line == null) {
                throw new IOException("Empty CSV file");
            }
            
            while ((line = br.readLine()) != null) {
                if (line.trim().isEmpty()) continue;
                
                String[] fields = line.split(",");
                if (fields.length < 8) continue;
                
                try {
                    double timestamp = Double.parseDouble(fields[0]);
                    String clientIp = fields[1];
                    String qname = fields[3];
                    int responseCode = Integer.parseInt(fields[5]);
                    
                    // Get or create client features
                    ClientFeatures features = clientStats.getOrDefault(clientIp, new ClientFeatures(clientIp));
                    
                    // Update query count and timestamps
                    features.totalQueries++;
                    features.firstTimestamp = Math.min(features.firstTimestamp, timestamp);
                    features.lastTimestamp = Math.max(features.lastTimestamp, timestamp);
                    
                    // Extract subdomain
                    String subdomain = extractSubdomain(qname);
                    if (!subdomain.isEmpty()) {
                        features.subdomainLengths.add(subdomain.length());
                        features.subdomains.add(subdomain);
                    }
                    
                    // Count NXDOMAIN responses (response_code = 3)
                    if (responseCode == 3) {
                        features.nxdomainCount++;
                    }
                    
                    clientStats.put(clientIp, features);
                } catch (NumberFormatException e) {
                    // Skip invalid lines
                    System.err.println("Skipping invalid line: " + line);
                }
            }
        }
        
        return clientStats;
    }
    
    /**
     * Calculate query rate per client (queries per minute)
     */
    private double calculateQueryRate(ClientFeatures features) {
        double timeWindow = features.lastTimestamp - features.firstTimestamp;
        // If time window is 0 or very small (single query or queries at same time),
        // we can't calculate a meaningful rate, so return 0
        if (timeWindow <= 0.1) {
            return 0.0;
        }
        // Convert to queries per minute
        return (features.totalQueries / timeWindow) * 60.0;
    }
    
    /**
     * Calculate average subdomain length
     */
    private double calculateAvgSubdomainLength(ClientFeatures features) {
        if (features.subdomainLengths.isEmpty()) {
            return 0.0;
        }
        int sum = features.subdomainLengths.stream().mapToInt(Integer::intValue).sum();
        return (double) sum / features.subdomainLengths.size();
    }
    
    /**
     * Calculate maximum subdomain length
     */
    private int calculateMaxSubdomainLength(ClientFeatures features) {
        if (features.subdomainLengths.isEmpty()) {
            return 0;
        }
        return features.subdomainLengths.stream().mapToInt(Integer::intValue).max().orElse(0);
    }
    
    /**
     * Calculate average entropy across all subdomains for a client
     */
    private double calculateAvgEntropy(ClientFeatures features) {
        if (features.subdomains.isEmpty()) {
            return 0.0;
        }
        double totalEntropy = 0.0;
        for (String subdomain : features.subdomains) {
            totalEntropy += calculateEntropy(subdomain);
        }
        return totalEntropy / features.subdomains.size();
    }
    
    /**
     * Calculate NXDOMAIN frequency (percentage of total queries)
     */
    private double calculateNxdomainFrequency(ClientFeatures features) {
        if (features.totalQueries == 0) {
            return 0.0;
        }
        return (double) features.nxdomainCount / features.totalQueries * 100.0;
    }
    
    /**
     * Print feature extraction results
     */
    public void printFeatures(Map<String, ClientFeatures> clientStats) {
        System.out.println("\n" + "=".repeat(100));
        System.out.println("DNS FEATURE EXTRACTION RESULTS");
        System.out.println("=".repeat(100));
        System.out.printf("%-18s %10s %12s %12s %12s %12s %12s %12s%n",
                "Client IP", "Queries", "Query Rate", "Avg Sub Len", "Max Sub Len", 
                "Avg Entropy", "NXDOMAIN %", "NXDOMAIN #");
        System.out.println("-".repeat(100));
        
        // Sort by query count (descending) for better readability
        List<Map.Entry<String, ClientFeatures>> sorted = new ArrayList<>(clientStats.entrySet());
        sorted.sort((a, b) -> Integer.compare(b.getValue().totalQueries, a.getValue().totalQueries));
        
        for (Map.Entry<String, ClientFeatures> entry : sorted) {
            ClientFeatures features = entry.getValue();
            
            double queryRate = calculateQueryRate(features);
            double avgSubLen = calculateAvgSubdomainLength(features);
            int maxSubLen = calculateMaxSubdomainLength(features);
            double avgEntropy = calculateAvgEntropy(features);
            double nxdomainFreq = calculateNxdomainFrequency(features);
            
            System.out.printf("%-18s %10d %12.2f %12.2f %12d %12.4f %12.2f%% %12d%n",
                    features.clientIp,
                    features.totalQueries,
                    queryRate,
                    avgSubLen,
                    maxSubLen,
                    avgEntropy,
                    nxdomainFreq,
                    features.nxdomainCount);
        }
        
        // Print summary statistics
        printSummaryStatistics(clientStats);
    }
    
    /**
     * Print overall summary statistics
     */
    private void printSummaryStatistics(Map<String, ClientFeatures> clientStats) {
        System.out.println("\n" + "=".repeat(100));
        System.out.println("SUMMARY STATISTICS");
        System.out.println("=".repeat(100));
        
        int totalClients = clientStats.size();
        int totalQueries = clientStats.values().stream().mapToInt(cf -> cf.totalQueries).sum();
        int totalNxdomain = clientStats.values().stream().mapToInt(cf -> cf.nxdomainCount).sum();
        
        double avgQueriesPerClient = totalClients > 0 ? (double) totalQueries / totalClients : 0;
        
        // Overall query rate statistics (filter out invalid values)
        List<Double> queryRates = new ArrayList<>();
        for (ClientFeatures cf : clientStats.values()) {
            double rate = calculateQueryRate(cf);
            if (rate >= 0 && rate < Double.MAX_VALUE && !Double.isNaN(rate) && !Double.isInfinite(rate)) {
                queryRates.add(rate);
            }
        }
        Collections.sort(queryRates);
        
        double minQueryRate = queryRates.isEmpty() ? 0 : queryRates.get(0);
        double maxQueryRate = queryRates.isEmpty() ? 0 : queryRates.get(queryRates.size() - 1);
        double medianQueryRate = queryRates.isEmpty() ? 0 : 
                queryRates.size() % 2 == 0 ?
                    (queryRates.get(queryRates.size() / 2 - 1) + queryRates.get(queryRates.size() / 2)) / 2.0 :
                    queryRates.get(queryRates.size() / 2);
        
        // Overall subdomain length statistics
        List<Integer> allSubdomainLengths = new ArrayList<>();
        for (ClientFeatures cf : clientStats.values()) {
            allSubdomainLengths.addAll(cf.subdomainLengths);
        }
        
        double avgSubdomainLength = allSubdomainLengths.isEmpty() ? 0 :
                allSubdomainLengths.stream().mapToInt(Integer::intValue).average().orElse(0);
        int maxSubdomainLength = allSubdomainLengths.isEmpty() ? 0 :
                allSubdomainLengths.stream().mapToInt(Integer::intValue).max().orElse(0);
        
        // Overall entropy statistics
        List<Double> allEntropies = new ArrayList<>();
        for (ClientFeatures cf : clientStats.values()) {
            for (String subdomain : cf.subdomains) {
                allEntropies.add(calculateEntropy(subdomain));
            }
        }
        
        double avgEntropy = allEntropies.isEmpty() ? 0 :
                allEntropies.stream().mapToDouble(Double::doubleValue).average().orElse(0);
        double maxEntropy = allEntropies.isEmpty() ? 0 :
                allEntropies.stream().mapToDouble(Double::doubleValue).max().orElse(0);
        
        // Overall NXDOMAIN frequency
        double overallNxdomainFreq = totalQueries > 0 ? (double) totalNxdomain / totalQueries * 100.0 : 0;
        
        System.out.printf("Total Clients: %d%n", totalClients);
        System.out.printf("Total Queries: %d%n", totalQueries);
        System.out.printf("Average Queries per Client: %.2f%n", avgQueriesPerClient);
        System.out.printf("Overall NXDOMAIN Frequency: %.2f%% (%d/%d)%n", 
                overallNxdomainFreq, totalNxdomain, totalQueries);
        System.out.println();
        System.out.println("Query Rate Statistics (queries/minute):");
        System.out.printf("  Min: %.2f, Median: %.2f, Max: %.2f%n", 
                minQueryRate, medianQueryRate, maxQueryRate);
        System.out.println();
        System.out.println("Subdomain Length Statistics:");
        System.out.printf("  Average: %.2f, Max: %d%n", avgSubdomainLength, maxSubdomainLength);
        System.out.println();
        System.out.println("Entropy Statistics (bits):");
        System.out.printf("  Average: %.4f, Max: %.4f%n", avgEntropy, maxEntropy);
        System.out.println("\n" + "=".repeat(100));
    }
    
    /**
     * Main method for testing and running feature extraction
     */
    public static void main(String[] args) {
        String csvFilePath = "./queries_export.csv";
        
        if (args.length > 0) {
            csvFilePath = args[0];
        }
        
        DNSFeatureExtractor extractor = new DNSFeatureExtractor();
        
        try {
            System.out.println("Reading DNS queries from: " + csvFilePath);
            Map<String, ClientFeatures> clientStats = extractor.extractFeaturesFromCsv(csvFilePath);
            
            System.out.println("Extracted features for " + clientStats.size() + " unique clients");
            extractor.printFeatures(clientStats);
            
        } catch (IOException e) {
            System.err.println("Error reading CSV file: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

