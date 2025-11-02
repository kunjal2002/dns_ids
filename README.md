# 🧠 DNS-Based Intrusion Detection System (DNS-IDS)

![Java](https://img.shields.io/badge/Java-17%2B-blue?logo=java)
![Maven](https://img.shields.io/badge/Build-Maven-orange?logo=apachemaven)
![SQLite](https://img.shields.io/badge/Database-SQLite-blue?logo=sqlite)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-In%20Progress-yellow)

---

## 📘 Overview

**DNS-IDS** is a system designed to **detect malicious DNS activity** (such as tunneling or data exfiltration) in real time by analyzing DNS traffic patterns.
This project is part of the **ECS 235 – Computer and Information Security** course at **UC Davis**.

The system:

* Captures DNS queries
* Extracts behavioral features
* Flags anomalies using **statistical thresholds** and **rule-based analysis**

---

## 🎯 Research Question

> How can real-time DNS traffic analysis identify malicious activity such as tunneling or data exfiltration?

We investigate whether anomalies in DNS query patterns — such as:

* High-entropy subdomains
* Unusually long subdomain names
* Repeated NXDOMAIN responses
* Abnormally high query rates per client

can serve as **reliable indicators of attack** without excessive false positives.

---



**Modules:**

1. **DNS Traffic Collector** – Captures DNS queries and stores them for processing.
   *Input:* `.pcap`, `.csv`, or live DNS stream
   *Output Fields:* timestamp, client IP, domain, query type, response code

2. **Feature Extraction Module** – Converts raw logs to numerical features:

   * Query rate per client
   * Domain name length
   * Subdomain entropy
   * NXDOMAIN response ratio

3. **Anomaly Detection Engine** – Uses rule-based and statistical thresholds to flag anomalies.

4. **Alerting & Visualization** – Displays real-time DNS traffic and anomaly alerts.

5. **Reporting Module** – Generates periodic anomaly summary reports.

---

## 🪠 Technology Stack

| Component      | Technology                                                                                                     |
| -------------- | -------------------------------------------------------------------------------------------------------------- |
| **Language**   | Java                                                                                                           |
| **Build Tool** | Maven                                                                                                          |
| **Database**   | SQLite (local)                                                                                                 |
| **Libraries**  | `org.xbill.dns` – DNS parsing<br>`com.google.gson` – Data handling<br>`JFreeChart` – Visualization *(planned)* |

---

## ⚙️ Setup Instructions

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/dns-ids.git
cd dns-ids
```

### 2. Install Java and Maven

Ensure you have:

* **Java 17+**
* **Apache Maven 3.8+**

Check versions:

```bash
java -version
mvn -version
```

### 3. Build the Project

```bash
mvn clean install
```

### 4. Run the Simulation

Simulate DNS traffic collection:

```bash
mvn exec:java -Dexec.mainClass="org.example.DNSCollector" -Dexec.args="simulate"
```

This will generate DNS query logs in a local file or database.

---

### 5. Run Feature Extraction

After collecting data:

```bash
mvn exec:java -Dexec.mainClass="org.example.FeatureExtractor"
```

---

### 6. Run Anomaly Detection

Once features are generated:

```bash
mvn exec:java -Dexec.mainClass="org.example.AnomalyDetector"
```

Anomalies will be printed in the console and stored in the output file.

---

## 🧮 Example Output

| Client IP    | Query Count | Avg Domain Length | NXDOMAIN Ratio | Entropy | Label      |
| ------------ | ----------- | ----------------- | -------------- | ------- | ---------- |
| 192.168.1.10 | 450         | 27.3              | 0.05           | 3.9     | Normal     |
| 192.168.1.12 | 2100        | 64.7              | 0.45           | 7.8     | Suspicious |

---

## 💾 Database Setup (Optional)

By default, a local **SQLite** database `dns_data.db` is created automatically.

To reset:

```bash
rm dns_data.db
```

A new one will be generated on the next run.

For external databases (e.g., MySQL), update credentials in:

```
src/main/resources/config.properties
```

---

## 📚 References

This project draws upon research in:

* DNS-based attack vectors and tunneling techniques
* Statistical anomaly detection in network security
* Real-world DNS exfiltration cases (e.g., **Mirai botnet**)

These informed our feature engineering and detection methodology.

---



## 🧾 Summary

The **DNS-IDS** system provides a foundation for **real-time detection** of DNS-based malicious activity using rule-based and statistical analysis.
It can be extended to handle larger datasets, real-world DNS streams, and advanced ML-driven anomaly detection.


---
