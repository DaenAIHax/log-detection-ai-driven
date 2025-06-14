#!/usr/bin/env python
# coding: utf-8

# In[5]:


# cascade_log_detection.py - Cascata Intelligente per Log Anomaly Detection

import pandas as pd
import numpy as np
import joblib
import tensorflow as tf
from sklearn.ensemble import IsolationForest, RandomForestClassifier
import os
import time
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder

# Fix compatibilità NumPy
if not hasattr(np, 'bool'):
    np.bool = bool
if not hasattr(np, 'int'):
    np.int = int    
if not hasattr(np, 'float'):
    np.float = float
if not hasattr(np, 'complex'):
    np.complex = complex

# Carica modelli pre-allenati (ora sono nella stessa directory)
model_isolation = joblib.load('isolation_forest.pkl')
model_random = joblib.load('random_forest.pkl')
model_lstm = tf.keras.models.load_model('lstm_model.h5')

# Carica dataset BGL
df_logs = pd.read_csv('test_logs_2.csv')  # Corretto: test_logs.csv non test_logs_2.csv

print("✅ Modelli e dataset caricati con successo!")
print(f"📊 Dataset shape: {df_logs.shape}")

# TODO: Implementare preprocessing
# TODO: Implementare cascata intelligente
# TODO: Implementare metriche performance


# In[6]:


def preprocess_bgl_features(df):
    """Preprocessing specifico per dataset BGL"""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.preprocessing import LabelEncoder
    import pandas as pd

    print("🔄 Preprocessing BGL features...")

    # 1. Severity encoding
    severity_encoder = LabelEncoder()
    severity_encoded = severity_encoder.fit_transform(df['severity'])

    # 2. Timestamp features
    df_features = pd.DataFrame()
    df_features['timestamp_unix'] = df['timestamp_unix']
    df_features['hour'] = pd.to_datetime(df['timestamp_unix'], unit='s').dt.hour
    df_features['day_of_week'] = pd.to_datetime(df['timestamp_unix'], unit='s').dt.dayofweek
    df_features['severity_encoded'] = severity_encoded

    # 3. Message length feature (semplice ma efficace)
    df_features['message_length'] = df['message'].str.len()

    # 4. TF-IDF delle prime 100 features più importanti
    tfidf = TfidfVectorizer(max_features=100, stop_words='english', lowercase=True)
    tfidf_features = tfidf.fit_transform(df['message']).toarray()

    # Combina tutte le features
    tfidf_df = pd.DataFrame(tfidf_features, columns=[f'tfidf_{i}' for i in range(tfidf_features.shape[1])])
    final_features = pd.concat([df_features.reset_index(drop=True), tfidf_df.reset_index(drop=True)], axis=1)

    print(f"   ✅ Features create: {final_features.shape}")
    return final_features


# In[7]:


def cascade_detection(df_logs, isolation_model, random_forest_model):
    """
    Cascata semplice a 2 stadi:
    Stage 1: Isolation Forest filtra log normali (veloce)
    Stage 2: Random Forest classifica solo i sospetti (preciso)
    """

    print("🚀 Avvio cascata detection...")
    start_time = time.time()

    # PREPROCESSING: Crea features appropriate
    X_processed = preprocess_bgl_features(df_logs)

    # STAGE 1: Isolation Forest - Filtro veloce
    print("📊 Stage 1: Isolation Forest filtering...")

    # Usa le prime features che dovrebbero matchare il training
    n_features_iso = isolation_model.n_features_in_
    X_stage1 = X_processed.iloc[:, :n_features_iso]

    # Stage 1: Predizione Isolation Forest
    stage1_predictions = isolation_model.predict(X_stage1)
    stage1_scores = isolation_model.decision_function(X_stage1)

    # Identifica log sospetti (anomalie = -1, normali = 1)
    suspicious_mask = stage1_predictions == -1
    normal_count = np.sum(stage1_predictions == 1)
    suspicious_count = np.sum(suspicious_mask)

    print(f"   ✅ Log normali filtrati: {normal_count} ({normal_count/len(df_logs)*100:.1f}%)")
    print(f"   ⚠️  Log sospetti per Stage 2: {suspicious_count} ({suspicious_count/len(df_logs)*100:.1f}%)")

    # STAGE 2: Random Forest solo sui sospetti
    print("🔍 Stage 2: Random Forest classification...")

    if suspicious_count == 0:
        print("   ℹ️  Nessun log sospetto trovato - tutti classificati come normali")
        final_predictions = np.ones(len(df_logs))  # Tutti normali
        confidence_scores = np.abs(stage1_scores)
    else:
        # Prepara dati sospetti per Random Forest
        n_features_rf = random_forest_model.n_features_in_
        X_stage2 = X_processed[suspicious_mask].iloc[:, :n_features_rf]

        # Stage 2: Predizione Random Forest
        stage2_predictions = random_forest_model.predict(X_stage2)
        stage2_probabilities = random_forest_model.predict_proba(X_stage2)

        # Combina risultati
        final_predictions = np.ones(len(df_logs))  # Inizia tutti normali
        final_predictions[suspicious_mask] = stage2_predictions  # Sovrascrivi i sospetti

        # Calcola confidence scores
        confidence_scores = np.abs(stage1_scores)
        confidence_scores[suspicious_mask] = np.max(stage2_probabilities, axis=1)

    # Risultati finali
    anomalies_count = np.sum(final_predictions == 0)  # Assumendo 0 = anomalia
    total_time = time.time() - start_time

    print(f"\n📈 RISULTATI CASCATA:")
    print(f"   🎯 Anomalie rilevate: {anomalies_count}")
    print(f"   ⚡ Tempo totale: {total_time:.2f}s")
    print(f"   🚀 Riduzione carico Stage 2: {(1-suspicious_count/len(df_logs))*100:.1f}%")

    return {
        'predictions': final_predictions,
        'confidence_scores': confidence_scores,
        'stage1_filtered': normal_count,
        'stage2_processed': suspicious_count,
        'total_time': total_time,
        'stage1_scores': stage1_scores
    }



# In[8]:


def lstm_apt_detection(df_logs, lstm_model, sequence_length=10, threshold=0.5):
    """
    Analisi LSTM separata per rilevamento APT
    Analizza l'intera sequenza temporale per pattern avanzati
    """

    print("🧠 Avvio LSTM APT Detection...")
    start_time = time.time()

    # Ordina i log per timestamp per analisi sequenziale
    df_sorted = df_logs.sort_values('timestamp_unix').reset_index(drop=True)

    # Prepara sequenze temporali complete
    print("   🔄 Preparando sequenze temporali...")
    timestamps = df_sorted['timestamp_unix'].values

    # Normalizza timestamps
    timestamps_norm = (timestamps - timestamps.min()) / (timestamps.max() - timestamps.min() + 1e-8)

    # Crea sequenze sliding window
    sequences = []
    sequence_indices = []  # Traccia gli indici originali

    for i in range(len(timestamps_norm) - sequence_length + 1):
        seq = timestamps_norm[i:i + sequence_length]
        sequences.append(seq)
        sequence_indices.append(list(range(i, i + sequence_length)))

    if len(sequences) == 0:
        print("   ⚠️  Dataset troppo piccolo per analisi sequenziale")
        return {
            'apt_detected': False,
            'suspicious_sequences': [],
            'confidence_scores': np.array([]),
            'total_time': time.time() - start_time
        }

    X_lstm = np.array(sequences).reshape(-1, sequence_length, 1)
    print(f"   ✅ Sequenze create: {X_lstm.shape}")

    # Predizione LSTM
    print("   🔍 Analizzando pattern temporali...")
    lstm_predictions = lstm_model.predict(X_lstm, verbose=0)
    lstm_scores = lstm_predictions.flatten()

    # Identifica sequenze sospette per APT
    apt_mask = lstm_scores > threshold
    apt_sequences = np.where(apt_mask)[0]

    print(f"   📊 Sequenze analizzate: {len(sequences)}")
    print(f"   ⚠️  Pattern APT rilevati: {len(apt_sequences)}")
    print(f"   🎯 Score medio: {np.mean(lstm_scores):.3f}")

    # Dettagli sequenze sospette
    suspicious_details = []
    if len(apt_sequences) > 0:
        for seq_idx in apt_sequences:
            log_indices = sequence_indices[seq_idx]
            suspicious_logs = df_sorted.iloc[log_indices]

            suspicious_details.append({
                'sequence_id': seq_idx,
                'confidence': lstm_scores[seq_idx],
                'log_indices': log_indices,
                'timespan': suspicious_logs['timestamp_unix'].max() - suspicious_logs['timestamp_unix'].min(),
                'severity_mix': suspicious_logs['severity'].value_counts().to_dict(),
                'sample_messages': suspicious_logs['message'].head(3).tolist()
            })

    total_time = time.time() - start_time

    print(f"\n📈 RISULTATI LSTM APT:")
    print(f"   🕒 Tempo analisi: {total_time:.3f}s")
    print(f"   🔍 APT rilevati: {'SÌ' if len(apt_sequences) > 0 else 'NO'}")
    if len(apt_sequences) > 0:
        max_confidence = np.max(lstm_scores[apt_sequences])
        print(f"   📊 Confidence massima: {max_confidence:.3f}")

    return {
        'apt_detected': len(apt_sequences) > 0,
        'suspicious_sequences': suspicious_details,
        'confidence_scores': lstm_scores,
        'total_time': total_time,
        'sequence_indices': sequence_indices
    }


# In[9]:


def generate_security_alerts(cascade_results, lstm_results):
    """
    Sistema di alert intelligente che combina risultati cascata + LSTM
    """

    print("\n🚨 Generazione Security Alerts...")

    alerts = []

    # ALERT 1: Anomalie da Cascata Forest
    cascade_anomalies = np.sum(cascade_results['predictions'] == 0)
    if cascade_anomalies > 0:
        alert = {
            'type': 'ANOMALY_DETECTED',
            'severity': 'MEDIUM',
            'source': 'Cascade Forest',
            'count': int(cascade_anomalies),
            'message': f"Rilevate {cascade_anomalies} anomalie nei log",
            'details': {
                'stage1_filtered': cascade_results['stage1_filtered'],
                'stage2_processed': cascade_results['stage2_processed'],
                'processing_time': cascade_results['total_time']
            }
        }
        alerts.append(alert)

    # ALERT 2: APT da LSTM
    if lstm_results['apt_detected']:
        apt_count = len(lstm_results['suspicious_sequences'])
        max_confidence = max([seq['confidence'] for seq in lstm_results['suspicious_sequences']])

        severity = 'HIGH' if max_confidence > 0.8 else 'MEDIUM' if max_confidence > 0.6 else 'LOW'

        alert = {
            'type': 'APT_PATTERN_DETECTED',
            'severity': severity,
            'source': 'LSTM Deep Analysis',
            'count': apt_count,
            'message': f"Rilevati {apt_count} pattern APT sospetti (max confidence: {max_confidence:.3f})",
            'details': {
                'max_confidence': float(max_confidence),
                'sequences': lstm_results['suspicious_sequences'][:3],  # Prime 3 per brevità
                'analysis_time': lstm_results['total_time']
            }
        }
        alerts.append(alert)

    # ALERT 3: Correlazione Cross-System
    if cascade_anomalies > 0 and lstm_results['apt_detected']:
        alert = {
            'type': 'CORRELATED_THREAT',
            'severity': 'HIGH',
            'source': 'Cross-System Analysis',
            'message': "Anomalie e pattern APT rilevati simultaneamente - possibile attacco coordinato",
            'details': {
                'anomaly_count': int(cascade_anomalies),
                'apt_patterns': len(lstm_results['suspicious_sequences']),
                'recommendation': 'Immediate investigation required'
            }
        }
        alerts.append(alert)

    # Stampa alerts
    if not alerts:
        print("   ✅ Nessun alert generato - sistema sicuro")
    else:
        print(f"   🚨 {len(alerts)} alert generati:")
        for i, alert in enumerate(alerts, 1):
            print(f"      {i}. [{alert['severity']}] {alert['type']}: {alert['message']}")

    return alerts


# In[10]:


# ESECUZIONE PARALLELA
print("\n" + "="*60)
print("🎯 SISTEMA DUAL DETECTION: FOREST CASCADE + LSTM APT")
print("="*60)

# 1. Cascata Forest (anomalie classiche)
print("\n1️⃣ CASCATA FOREST - Anomalie Classiche")
cascade_results = cascade_detection(df_logs, model_isolation, model_random)

# 2. LSTM separato (APT detection)  
print("\n2️⃣ LSTM ANALYSIS - APT Detection")
lstm_results = lstm_apt_detection(df_logs, model_lstm)


# In[13]:


# 3. Sistema di alert intelligente
print("\n3️⃣ ALERT SYSTEM")
security_alerts = generate_security_alerts(cascade_results, lstm_results)

print(f"\n🎯 SUMMARY:")
print(f"   Forest Anomalies: {np.sum(cascade_results['predictions'] == 0)}")
print(f"   APT Patterns: {len(lstm_results['suspicious_sequences']) if lstm_results['apt_detected'] else 0}")
print(f"   Security Alerts: {len(security_alerts)}")
print(f"   Total Processing Time: {cascade_results['total_time'] + lstm_results['total_time']:.3f}s")



# In[14]:


# Esegui la cascata
print("\n" + "="*50)
print("🎯 AVVIO CASCATA INTELLIGENTE")
print("="*50)

results = cascade_detection(df_logs, model_isolation, model_random)

print(f"\n✅ Cascata completata!")
print(f"📊 Predictions shape: {results['predictions'].shape}")
print(f"🎯 Anomalie totali: {np.sum(results['predictions'] == 0)}")


# In[ ]:




