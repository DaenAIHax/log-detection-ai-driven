# log-detection-ai-driven

# Log Detection AI-Driven

> Multi-pipeline AI system for intelligent log anomaly detection and cybersecurity threat analysis

## Overview

This project implements an intelligent log analysis system featuring **3 specialized ML pipelines** designed to detect different types of cybersecurity threats. The system combines supervised and unsupervised learning approaches to provide comprehensive security monitoring.

##  Architecture

The system is built around three complementary detection pipelines:

### **Pipeline 1: Cascade Detection** 
- **Isolation Forest** (Unsupervised) → Filters normal logs quickly
- **Random Forest** (Supervised) → Analyzes suspicious logs with precision
- **Goal**: Reduce false positives while maintaining high detection accuracy
- **Efficiency**: ~70% computational load reduction through intelligent filtering

### **Pipeline 2: APT Pattern Detection** 
- **LSTM Neural Network** → Analyzes temporal patterns in log sequences
- **Focus**: Advanced Persistent Threats (APT) detection
- **Method**: Sequential pattern analysis for sophisticated attack identification

### **Pipeline 3: Zero-Day Detection** 
- **Random Forest** → Analyzes logs classified as "normal" by Pipeline 1
- **Goal**: Identify subtle anomalies and potential zero-day attacks
- **Status**: *Not implemented due to computational constraints*

## Proof of Concept Status

**Current Implementation:**
-  Complete architecture for Pipelines 1 & 2 implemented
-  Custom data parsing and preprocessing pipeline implemented
-  Fine-tuned 3 models on 100K subset of NASA BGL dataset (1B+ total logs available)
  - **Isolation Forest**: Trained on 100% normal logs for baseline establishment
  - **Random Forest**: Fine-tuned on balanced dataset (50% normal, 50% anomalies)
  - **LSTM**: Fine-tuned on timestamp sequences for temporal pattern recognition
-  Limited by computational resources for full dataset training
-  Focus on architecture design and ML pipeline validation

##  Results & Limitations

### Current Performance
- **Training Data**: 100K logs from NASA BGL dataset
- **Computational Constraints**: Limited hardware prevented full dataset utilization
- **Status**: Proof of Concept - architecture validated, performance optimization pending

### Known Issues 
- Models undertrained due to dataset size constraints
- Performance metrics not production-ready
- Requires extensive validation with full dataset
- Zero-day pipeline not implemented

### What Works Well
- Multi-pipeline architecture successfully implemented
- Cascade design demonstrates computational efficiency
- Real-time processing capability validated
- Alert correlation system functional
- Clean, modular code structure

##  Data Processing & Model Training

### Data Preprocessing Pipeline
- **Log Parsing**: Custom preprocessing for NASA BGL log format
- **Feature Engineering**: TF-IDF vectorization, temporal features, severity encoding
- **Data Preparation**: Specialized datasets for each model type

### Model Fine-tuning Strategy
- **Isolation Forest**: Fine-tuned on 100% normal logs to establish baseline behavior
- **Random Forest**: Fine-tuned on balanced dataset (50% normal logs, 50% anomalies)
- **LSTM**: Fine-tuned on timestamp sequences for temporal pattern learning

## Tech Stack

- **Python 3.8+**
- **TensorFlow 2.x** - LSTM implementation
- **Scikit-learn** - Isolation Forest, Random Forest
- **Pandas** - Data processing
- **NumPy** - Numerical operations
- **Joblib** - Model serialization

## Quick Start


# Clone repository
git clone https://github.com/DaenAIHax/log-detection-ai-driven
cd log-detection-ai-driven

# Install dependencies
pip install -r requirements.txt

# Run detection system
python cascade_log_detection.py


## Project Structure

log-detection-ai-driven/
├── cascade_log_detection.py    # Main detection system
├── models/                     # Fine-tuned models
│   ├── isolation_forest.pkl
│   ├── random_forest.pkl
│   └── lstm_model.h5
├── data/
│   └── test_logs_2.csv        # Sample log data
├── requirements.txt           # Dependencies
└── README.md                 # This file


## Key Learnings

- Data Preprocessing: Implemented custom parsing pipeline for NASA BGL format
- Model Specialization: Different training approaches for different detection purposes
- Resource Planning: Dataset size critically impacts ML model performance
- Architecture Design: Pipeline approach allows modular threat detection
- Real-world Constraints: Computational limitations are common in ML projects
- Fine-tuning Strategy: Specialized datasets improve model focus and performance

## Future Improvements

- Cloud training with full NASA BGL dataset (AWS/GCP)
- Implement Pipeline 3 (Zero-day detection)
- Hyperparameter optimization with proper validation
- Real-time streaming log processing
- Performance benchmarking with production data
- Integration with SIEM systems

## Requirements

tensorflow==2.12.0
scikit-learn==1.3.0
pandas==2.0.3
numpy==1.24.3
joblib==1.3.2


## Project Goals Achieved

 System Architecture: Designed scalable multi-pipeline detection system  
 ML Integration: Combined supervised/unsupervised learning approaches  
 Cybersecurity Focus: Implemented APT and anomaly detection strategies  
 Code Quality: Clean, documented, modular implementation  
 Realistic Scope: Honest assessment of limitations and constraints  



*This project demonstrates ML system design and cybersecurity concepts implementation. Focus on architecture and methodology rather than performance metrics due to computational constraints.*
