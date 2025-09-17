"""
SentinelAI ML Training Pipeline
AI-Powered Next-Generation Firewall

This module provides machine learning model training for encrypted traffic classification
and anomaly detection in network flows.
"""

import os
import json
import numpy as np
import pandas as pd
import pickle
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path

# Deep Learning
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers, models
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score

# Data processing
import matplotlib.pyplot as plt
import seaborn as sns

class DataPreprocessor:
    """Handles data preprocessing for network flow features"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = None
        
    def load_datasets(self) -> Dict[str, pd.DataFrame]:
        """Load and combine multiple threat detection datasets"""
        datasets = {}
        
        # Load UNSW-NB15 dataset (if available)
        unsw_path = self.config.get('datasets', {}).get('unsw_nb15_path')
        if unsw_path and os.path.exists(unsw_path):
            print("Loading UNSW-NB15 dataset...")
            datasets['unsw'] = pd.read_csv(unsw_path)
            
        # Load CICIDS2017 dataset (if available)
        cicids_path = self.config.get('datasets', {}).get('cicids2017_path')
        if cicids_path and os.path.exists(cicids_path):
            print("Loading CICIDS2017 dataset...")
            datasets['cicids'] = pd.read_csv(cicids_path)
            
        # Generate synthetic data if no real datasets available
        if not datasets:
            print("No real datasets found, generating synthetic data...")
            datasets['synthetic'] = self.generate_synthetic_data(10000)
            
        return datasets
    
    def generate_synthetic_data(self, n_samples: int) -> pd.DataFrame:
        """Generate synthetic network flow data for testing"""
        np.random.seed(42)
        
        # Generate features similar to our feature extractor
        data = {
            'flow_duration': np.random.exponential(30, n_samples),  # seconds
            'total_bytes': np.random.lognormal(8, 2, n_samples),
            'packet_count': np.random.poisson(50, n_samples),
            'pkt_size_mean': np.random.normal(800, 400, n_samples),
            'pkt_size_std': np.random.exponential(200, n_samples),
            'pkt_size_median': np.random.normal(750, 350, n_samples),
            'iat_mean': np.random.exponential(0.1, n_samples),
            'iat_std': np.random.exponential(0.05, n_samples),
            'burstiness': np.random.exponential(1.5, n_samples),
            'periodicity': np.random.uniform(-1, 1, n_samples),
            'bytes_per_second': np.random.lognormal(10, 2, n_samples),
            'packets_per_second': np.random.poisson(10, n_samples),
            'has_sni': np.random.choice([0, 1], n_samples, p=[0.3, 0.7]),
            'sni_entropy': np.random.uniform(0, 4, n_samples),
            'ja3_present': np.random.choice([0, 1], n_samples, p=[0.4, 0.6]),
            'port_number': np.random.choice([80, 443, 22, 25, 53, 993, 8080], n_samples),
            'is_tcp': np.random.choice([0, 1], n_samples, p=[0.2, 0.8]),
            'is_common_port': np.random.choice([0, 1], n_samples, p=[0.3, 0.7]),
            'packet_size_entropy': np.random.uniform(0, 4, n_samples),
            'small_packet_ratio': np.random.beta(2, 5, n_samples),
            'large_packet_ratio': np.random.beta(1, 10, n_samples),
        }
        
        # Generate labels based on heuristics
        labels = []
        for i in range(n_samples):
            # Malicious traffic heuristics
            score = 0
            
            # High burstiness might indicate C2 traffic
            if data['burstiness'][i] > 3.0:
                score += 0.3
                
            # Unusual packet sizes
            if data['pkt_size_std'][i] > 500:
                score += 0.2
                
            # High bytes per second on non-standard ports
            if data['bytes_per_second'][i] > 100000 and data['is_common_port'][i] == 0:
                score += 0.4
                
            # Low entropy (encrypted tunnels)
            if data['packet_size_entropy'][i] < 1.0:
                score += 0.3
                
            # Many small packets (potential exfiltration)
            if data['small_packet_ratio'][i] > 0.8:
                score += 0.2
                
            # Classify based on score
            if score > 0.6:
                labels.append('malicious')
            elif score > 0.3:
                labels.append('suspicious')
            else:
                labels.append('benign')
        
        data['label'] = labels
        return pd.DataFrame(data)
    
    def preprocess_features(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """Preprocess features for model training"""
        # Separate features and labels
        if 'label' in df.columns:
            y = df['label'].values
            X = df.drop('label', axis=1)
        else:
            y = None
            X = df
            
        # Handle missing values
        X = X.fillna(X.median())
        
        # Store feature columns
        self.feature_columns = X.columns.tolist()
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Encode labels if present
        if y is not None:
            y_encoded = self.label_encoder.fit_transform(y)
        else:
            y_encoded = None
            
        return X_scaled, y_encoded, self.feature_columns
    
    def save_preprocessors(self, save_dir: str):
        """Save preprocessing objects"""
        os.makedirs(save_dir, exist_ok=True)
        
        with open(os.path.join(save_dir, 'scaler.pkl'), 'wb') as f:
            pickle.dump(self.scaler, f)
            
        with open(os.path.join(save_dir, 'label_encoder.pkl'), 'wb') as f:
            pickle.dump(self.label_encoder, f)
            
        with open(os.path.join(save_dir, 'feature_columns.json'), 'w') as f:
            json.dump(self.feature_columns, f)

class CNNTrafficClassifier:
    """CNN model for encrypted traffic classification"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.model = None
        self.history = None
        
    def build_model(self, input_shape: Tuple[int], num_classes: int) -> keras.Model:
        """Build CNN model architecture"""
        model = models.Sequential([
            # Reshape for 1D CNN
            layers.Reshape((input_shape[0], 1), input_shape=input_shape),
            
            # First convolutional block
            layers.Conv1D(64, 3, activation='relu'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(2),
            layers.Dropout(0.3),
            
            # Second convolutional block
            layers.Conv1D(128, 3, activation='relu'),
            layers.BatchNormalization(),
            layers.MaxPooling1D(2),
            layers.Dropout(0.3),
            
            # Third convolutional block
            layers.Conv1D(256, 3, activation='relu'),
            layers.BatchNormalization(),
            layers.GlobalMaxPooling1D(),
            layers.Dropout(0.5),
            
            # Dense layers
            layers.Dense(256, activation='relu'),
            layers.BatchNormalization(),
            layers.Dropout(0.5),
            layers.Dense(128, activation='relu'),
            layers.Dropout(0.3),
            
            # Output layer
            layers.Dense(num_classes, activation='softmax')
        ])
        
        # Compile model
        model.compile(
            optimizer=keras.optimizers.Adam(learning_rate=0.001),
            loss='sparse_categorical_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        self.model = model
        return model
    
    def train(self, X_train: np.ndarray, y_train: np.ndarray, 
              X_val: np.ndarray, y_val: np.ndarray) -> keras.callbacks.History:
        """Train the CNN model"""
        
        # Callbacks
        callbacks = [
            keras.callbacks.EarlyStopping(
                monitor='val_loss', patience=10, restore_best_weights=True
            ),
            keras.callbacks.ReduceLROnPlateau(
                monitor='val_loss', factor=0.5, patience=5, min_lr=1e-7
            ),
            keras.callbacks.ModelCheckpoint(
                'models/cnn_traffic_classifier.h5',
                monitor='val_accuracy', save_best_only=True
            )
        ]
        
        # Train model
        self.history = self.model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=self.config.get('epochs', 100),
            batch_size=self.config.get('batch_size', 64),
            callbacks=callbacks,
            verbose=1
        )
        
        return self.history
    
    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, float]:
        """Evaluate model performance"""
        # Predictions
        y_pred_proba = self.model.predict(X_test)
        y_pred = np.argmax(y_pred_proba, axis=1)
        
        # Metrics
        test_loss, test_acc, test_precision, test_recall = self.model.evaluate(X_test, y_test, verbose=0)
        
        # Classification report
        print("Classification Report:")
        print(classification_report(y_test, y_pred))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print("Confusion Matrix:")
        print(cm)
        
        # ROC AUC for multi-class
        try:
            auc = roc_auc_score(y_test, y_pred_proba, multi_class='ovr', average='weighted')
        except:
            auc = 0.0
        
        metrics = {
            'test_loss': test_loss,
            'test_accuracy': test_acc,
            'test_precision': test_precision,
            'test_recall': test_recall,
            'auc_score': auc
        }
        
        return metrics

class AnomalyDetector:
    """Anomaly detection using Isolation Forest and DBSCAN"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.isolation_forest = None
        self.dbscan = None
        
    def train_isolation_forest(self, X_train: np.ndarray) -> IsolationForest:
        """Train Isolation Forest for anomaly detection"""
        self.isolation_forest = IsolationForest(
            contamination=self.config.get('contamination', 0.1),
            random_state=42,
            n_estimators=100
        )
        
        self.isolation_forest.fit(X_train)
        return self.isolation_forest
    
    def train_dbscan(self, X_train: np.ndarray) -> DBSCAN:
        """Train DBSCAN for anomaly detection"""
        self.dbscan = DBSCAN(
            eps=self.config.get('eps', 0.5),
            min_samples=self.config.get('min_samples', 5)
        )
        
        self.dbscan.fit(X_train)
        return self.dbscan
    
    def predict_anomalies(self, X: np.ndarray) -> Dict[str, np.ndarray]:
        """Predict anomalies using both methods"""
        results = {}
        
        if self.isolation_forest:
            # Isolation Forest predictions (-1 for anomaly, 1 for normal)
            if_pred = self.isolation_forest.predict(X)
            if_scores = self.isolation_forest.decision_function(X)
            results['isolation_forest'] = {
                'predictions': if_pred,
                'scores': if_scores
            }
        
        if self.dbscan:
            # DBSCAN predictions (-1 for noise/anomaly, >=0 for cluster)
            db_pred = self.dbscan.fit_predict(X)
            results['dbscan'] = {
                'predictions': db_pred
            }
        
        return results

class ModelExporter:
    """Export trained models for deployment"""
    
    @staticmethod
    def export_to_onnx(keras_model: keras.Model, output_path: str, input_shape: Tuple[int]):
        """Export Keras model to ONNX format"""
        try:
            import tf2onnx
            
            # Convert to ONNX
            onnx_model, _ = tf2onnx.convert.from_keras(
                keras_model, 
                input_signature=[tf.TensorSpec(shape=(None,) + input_shape, dtype=tf.float32)]
            )
            
            # Save ONNX model
            with open(output_path, 'wb') as f:
                f.write(onnx_model.SerializeToString())
                
            print(f"Model exported to ONNX: {output_path}")
        except ImportError:
            print("tf2onnx not available, saving as TensorFlow SavedModel format")
            keras_model.save(output_path.replace('.onnx', '_saved_model'))
    
    @staticmethod
    def export_sklearn_model(model, output_path: str):
        """Export scikit-learn model"""
        with open(output_path, 'wb') as f:
            pickle.dump(model, f)
        print(f"Sklearn model exported: {output_path}")

def main():
    """Main training pipeline"""
    # Configuration
    config = {
        'datasets': {
            'unsw_nb15_path': './datasets/UNSW_NB15_training-set.csv',
            'cicids2017_path': './datasets/CICIDS2017.csv'
        },
        'epochs': 50,
        'batch_size': 64,
        'contamination': 0.1,
        'eps': 0.5,
        'min_samples': 5
    }
    
    print("Starting SentinelAI ML Training Pipeline...")
    
    # Create output directories
    os.makedirs('models', exist_ok=True)
    os.makedirs('preprocessors', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    
    # Data preprocessing
    print("\n1. Data Preprocessing...")
    preprocessor = DataPreprocessor(config)
    datasets = preprocessor.load_datasets()
    
    # Combine datasets
    all_data = pd.concat(datasets.values(), ignore_index=True)
    print(f"Total samples: {len(all_data)}")
    print(f"Label distribution:\n{all_data['label'].value_counts()}")
    
    # Preprocess features
    X, y, feature_columns = preprocessor.preprocess_features(all_data)
    preprocessor.save_preprocessors('preprocessors')
    
    # Split data
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.4, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, random_state=42, stratify=y_temp
    )
    
    print(f"Training samples: {len(X_train)}")
    print(f"Validation samples: {len(X_val)}")
    print(f"Test samples: {len(X_test)}")
    
    # Train CNN classifier
    print("\n2. Training CNN Traffic Classifier...")
    cnn_classifier = CNNTrafficClassifier(config)
    cnn_model = cnn_classifier.build_model(
        input_shape=(X_train.shape[1],), 
        num_classes=len(np.unique(y))
    )
    
    print(f"CNN Model Architecture:")
    cnn_model.summary()
    
    # Train CNN
    history = cnn_classifier.train(X_train, y_train, X_val, y_val)
    
    # Evaluate CNN
    cnn_metrics = cnn_classifier.evaluate(X_test, y_test)
    print(f"CNN Metrics: {cnn_metrics}")
    
    # Export CNN model
    ModelExporter.export_to_onnx(
        cnn_model, 
        'models/encrypted_traffic_cnn_v1.onnx',
        (X_train.shape[1],)
    )
    
    # Train anomaly detection models
    print("\n3. Training Anomaly Detection Models...")
    anomaly_detector = AnomalyDetector(config)
    
    # Use only benign traffic for training anomaly detectors
    benign_mask = y_train == preprocessor.label_encoder.transform(['benign'])[0]
    X_benign = X_train[benign_mask]
    
    # Train Isolation Forest
    isolation_forest = anomaly_detector.train_isolation_forest(X_benign)
    ModelExporter.export_sklearn_model(
        isolation_forest, 
        'models/anomaly_isolation_forest_v1.pkl'
    )
    
    # Train DBSCAN
    dbscan = anomaly_detector.train_dbscan(X_benign)
    ModelExporter.export_sklearn_model(
        dbscan, 
        'models/anomaly_dbscan_v1.pkl'
    )
    
    # Evaluate anomaly detection
    anomaly_results = anomaly_detector.predict_anomalies(X_test)
    
    if 'isolation_forest' in anomaly_results:
        if_pred = anomaly_results['isolation_forest']['predictions']
        if_anomalies = np.sum(if_pred == -1)
        print(f"Isolation Forest detected {if_anomalies}/{len(X_test)} anomalies")
    
    if 'dbscan' in anomaly_results:
        db_pred = anomaly_results['dbscan']['predictions']
        db_anomalies = np.sum(db_pred == -1)
        print(f"DBSCAN detected {db_anomalies}/{len(X_test)} anomalies")
    
    # Save training metadata
    metadata = {
        'timestamp': datetime.now().isoformat(),
        'dataset_size': len(all_data),
        'feature_count': len(feature_columns),
        'model_metrics': cnn_metrics,
        'feature_columns': feature_columns
    }
    
    with open('models/training_metadata.json', 'w') as f:
        json.dump(metadata, f, indent=2)
    
    print("\nTraining completed successfully!")
    print("Models saved in ./models/")
    print("Preprocessors saved in ./preprocessors/")

if __name__ == "__main__":
    main()