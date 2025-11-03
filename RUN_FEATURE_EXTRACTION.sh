#!/bin/bash

# DNS Feature Extraction Module - Quick Run Script
# This script runs the feature extraction on your DNS queries CSV file

echo "=========================================="
echo "DNS Feature Extraction Module"
echo "=========================================="
echo ""

# Check if CSV file exists
CSV_FILE="queries_export.csv"
if [ ! -f "$CSV_FILE" ]; then
    echo "Error: $CSV_FILE not found!"
    echo "Please ensure queries_export.csv is in the current directory."
    exit 1
fi

# Run the feature extractor
echo "Extracting features from: $CSV_FILE"
echo ""

java -cp "target/classes:target/cis_project-1.0-SNAPSHOT.jar" \
    org.example.DNSFeatureExtractor "$CSV_FILE"

echo ""
echo "=========================================="
echo "Feature extraction complete!"
echo "=========================================="

