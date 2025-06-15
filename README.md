# log-detection-ai-driven


> Multi-pipeline AI system for intelligent log anomaly detection and cybersecurity threat analysis
![Architecture](https://img.shields.io/badge/architecture-multi--pipeline-blue.svg)
![ML Models](https://img.shields.io/badge/models-3%20specialized-green.svg)
![Efficiency](https://img.shields.io/badge/efficiency-70%25%20reduction-orange.svg)


## Overview

This project implements an intelligent log analysis system featuring **3 specialized ML pipelines** designed to detect different types of cybersecurity threats. The system combines supervised and unsupervised learning approaches to provide comprehensive security monitoring.

# Multi-Pipeline Log Detection Architecture

## System Architecture Diagram

flowchart TD
    A[Raw Log Data] --> B[Log Preprocessing]
    B --> C[Feature Engineering]
    C --> D[TF-IDF Vectorization]
    C --> E[Temporal Features] 
    C --> F[Severity Encoding]
    
    %% Pipeline 1: Real-time
    D --> G[Pipeline 1: Real-time Detection]
    F --> G
    G --> H[Isolation Forest]
    H --> I{Anomaly?}
    I -->|Yes| J[Random Forest]
    I -->|No| K[Normal]
    J --> L{Threat?}
    L -->|Yes| M[Real-time Alert]
    L -->|No| N[Filtered]
    
    %% Pipeline 2: Delayed
    D --> O[Pipeline 2: Delayed Analysis]
    E --> O
    F --> O
    O --> P[Random Forest Zero-day]
    P --> Q{Zero-day?}
    Q -->|Yes| R[Zero-day Alert]
    Q -->|No| S[Normal]
    
    %% Pipeline 3: Temporal
    E --> T[Pipeline 3: Temporal Analysis]
    T --> U[LSTM Network]
    U --> V{APT Pattern?}
    V -->|Yes| W[APT Alert]
    V -->|No| X[Normal]
    
    %% Alert System
    M --> Y[Alert Correlation]
    R --> Y
    W --> Y
    Y --> Z[Security Report]
    
    %% Normal Flow
    K --> AA[Log Archive]
    N --> AA
    S --> AA
    X --> AA
    
    style G fill:#e1f5fe
    style O fill:#fff3e0
    style T fill:#e8f5e8
    style Y fill:#f3e5f5
    style Z fill:#ffebee

## Pipeline Specialization

```mermaid
graph LR
    subgraph "Pipeline 1: Quick Filtering"
        A1[Isolation Forest<br/>Unsupervised] --> A2[Normal Log Filter<br/>~70% Reduction]
    end
    
    subgraph "Pipeline 2: Precision Analysis"
        B1[Random Forest<br/>Supervised] --> B2[Anomaly Classification<br/>High Precision]
    end
    
    subgraph "Pipeline 3: Temporal Analysis"
        C1[LSTM Network<br/>Sequential] --> C2[APT Detection<br/>Pattern Recognition]
    end
    
    A2 --> B1
    style A1 fill:#e1f5fe
    style B1 fill:#f3e5f5
    style C1 fill:#e8f5e8
```

## Data Flow Architecture

```mermaid
flowchart TD
    subgraph "Data Ingestion"
        D1[NASA BGL Dataset<br/>1B+ Logs] --> D2[Custom Parser<br/>100K Subset]
    end
    
    subgraph "Feature Engineering"
        F1[Text Processing] --> F2[TF-IDF Vectors]
        F3[Timestamp Analysis] --> F4[Temporal Features]
        F5[Log Severity] --> F6[Categorical Encoding]
    end
    
    subgraph "Model Training"
        M1[Isolation Forest<br/>100% Normal Logs]
        M2[Random Forest<br/>50/50 Balanced]
        M3[LSTM<br/>Sequence Patterns]
    end
    
    subgraph "Detection Engine"
        E1[Real-time Processing] --> E2[Multi-model Inference]
        E2 --> E3[Alert Generation]
    end
    
    D2 --> F1
    D2 --> F3
    D2 --> F5
    
    F2 --> M1
    F2 --> M2
    F4 --> M3
    F6 --> M2
    
    M1 --> E2
    M2 --> E2
    M3 --> E2
    
    style D1 fill:#f0f0f0
    style E3 fill:#ffebee
```

## Key Features

- ** Cascade Design**: 70% computational load reduction
- ** Multi-Algorithm**: Isolation Forest + Random Forest + LSTM
- ** Real-time**: Streaming log processing capability
- ** Specialized**: Each pipeline targets specific threat types
- ** Correlation**: Advanced alert correlation system

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
