"""
Model evaluation and testing utilities for SentinelAI
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report, confusion_matrix, roc_curve, auc,
    precision_recall_curve, average_precision_score
)
from typing import Dict, List, Tuple
import json

class ModelEvaluator:
    """Comprehensive model evaluation utilities"""
    
    def __init__(self, model_name: str):
        self.model_name = model_name
        self.results = {}
    
    def evaluate_classification(self, y_true: np.ndarray, y_pred: np.ndarray, 
                              y_pred_proba: np.ndarray = None, 
                              class_names: List[str] = None) -> Dict:
        """Comprehensive classification evaluation"""
        
        # Basic metrics
        report = classification_report(y_true, y_pred, output_dict=True)
        cm = confusion_matrix(y_true, y_pred)
        
        results = {
            'classification_report': report,
            'confusion_matrix': cm.tolist(),
            'accuracy': report['accuracy'],
            'macro_avg': report['macro avg'],
            'weighted_avg': report['weighted avg']
        }
        
        # ROC curves and AUC (for binary/multiclass)
        if y_pred_proba is not None:
            try:
                # Binary classification
                if len(np.unique(y_true)) == 2:
                    fpr, tpr, _ = roc_curve(y_true, y_pred_proba[:, 1])
                    auc_score = auc(fpr, tpr)
                    results['roc_auc'] = auc_score
                    results['roc_curve'] = {'fpr': fpr.tolist(), 'tpr': tpr.tolist()}
                    
                    # Precision-Recall curve
                    precision, recall, _ = precision_recall_curve(y_true, y_pred_proba[:, 1])
                    ap_score = average_precision_score(y_true, y_pred_proba[:, 1])
                    results['average_precision'] = ap_score
                    results['pr_curve'] = {'precision': precision.tolist(), 'recall': recall.tolist()}
                
                # Multiclass - compute AUC for each class
                else:
                    from sklearn.metrics import roc_auc_score
                    auc_score = roc_auc_score(y_true, y_pred_proba, multi_class='ovr', average='weighted')
                    results['roc_auc_weighted'] = auc_score
                    
            except Exception as e:
                print(f"Warning: Could not compute ROC/PR curves: {e}")
        
        self.results['classification'] = results
        return results
    
    def evaluate_anomaly_detection(self, y_true_anomaly: np.ndarray, 
                                 y_pred_anomaly: np.ndarray,
                                 anomaly_scores: np.ndarray = None) -> Dict:
        """Evaluate anomaly detection performance"""
        
        # Convert to binary (1 for anomaly, 0 for normal)
        y_true_binary = (y_true_anomaly == -1).astype(int)
        y_pred_binary = (y_pred_anomaly == -1).astype(int)
        
        # Classification metrics
        report = classification_report(y_true_binary, y_pred_binary, output_dict=True)
        cm = confusion_matrix(y_true_binary, y_pred_binary)
        
        # Calculate specific anomaly detection metrics
        tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
        
        results = {
            'classification_report': report,
            'confusion_matrix': cm.tolist(),
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'specificity': specificity,
            'true_positives': int(tp),
            'false_positives': int(fp),
            'true_negatives': int(tn),
            'false_negatives': int(fn)
        }
        
        # ROC curve for anomaly scores
        if anomaly_scores is not None:
            try:
                fpr, tpr, thresholds = roc_curve(y_true_binary, -anomaly_scores)  # Negative because lower scores = more anomalous
                auc_score = auc(fpr, tpr)
                results['roc_auc'] = auc_score
                results['roc_curve'] = {
                    'fpr': fpr.tolist(), 
                    'tpr': tpr.tolist(),
                    'thresholds': thresholds.tolist()
                }
            except Exception as e:
                print(f"Warning: Could not compute ROC curve for anomaly detection: {e}")
        
        self.results['anomaly_detection'] = results
        return results
    
    def plot_confusion_matrix(self, cm: np.ndarray, class_names: List[str] = None, 
                            save_path: str = None):
        """Plot confusion matrix"""
        plt.figure(figsize=(8, 6))
        
        if class_names is None:
            class_names = [f'Class {i}' for i in range(len(cm))]
        
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                   xticklabels=class_names, yticklabels=class_names)
        plt.title(f'Confusion Matrix - {self.model_name}')
        plt.xlabel('Predicted')
        plt.ylabel('Actual')
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def plot_roc_curve(self, save_path: str = None):
        """Plot ROC curve"""
        if 'classification' in self.results and 'roc_curve' in self.results['classification']:
            plt.figure(figsize=(8, 6))
            
            fpr = self.results['classification']['roc_curve']['fpr']
            tpr = self.results['classification']['roc_curve']['tpr']
            auc_score = self.results['classification']['roc_auc']
            
            plt.plot(fpr, tpr, linewidth=2, label=f'ROC Curve (AUC = {auc_score:.3f})')
            plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random Classifier')
            
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title(f'ROC Curve - {self.model_name}')
            plt.legend(loc="lower right")
            plt.grid(True, alpha=0.3)
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.show()
    
    def plot_training_history(self, history, save_path: str = None):
        """Plot training history for neural networks"""
        fig, axes = plt.subplots(2, 2, figsize=(15, 10))
        
        # Training & validation loss
        axes[0, 0].plot(history.history['loss'], label='Training Loss')
        axes[0, 0].plot(history.history['val_loss'], label='Validation Loss')
        axes[0, 0].set_title('Model Loss')
        axes[0, 0].set_xlabel('Epoch')
        axes[0, 0].set_ylabel('Loss')
        axes[0, 0].legend()
        axes[0, 0].grid(True, alpha=0.3)
        
        # Training & validation accuracy
        axes[0, 1].plot(history.history['accuracy'], label='Training Accuracy')
        axes[0, 1].plot(history.history['val_accuracy'], label='Validation Accuracy')
        axes[0, 1].set_title('Model Accuracy')
        axes[0, 1].set_xlabel('Epoch')
        axes[0, 1].set_ylabel('Accuracy')
        axes[0, 1].legend()
        axes[0, 1].grid(True, alpha=0.3)
        
        # Training & validation precision
        if 'precision' in history.history:
            axes[1, 0].plot(history.history['precision'], label='Training Precision')
            axes[1, 0].plot(history.history['val_precision'], label='Validation Precision')
            axes[1, 0].set_title('Model Precision')
            axes[1, 0].set_xlabel('Epoch')
            axes[1, 0].set_ylabel('Precision')
            axes[1, 0].legend()
            axes[1, 0].grid(True, alpha=0.3)
        
        # Training & validation recall
        if 'recall' in history.history:
            axes[1, 1].plot(history.history['recall'], label='Training Recall')
            axes[1, 1].plot(history.history['val_recall'], label='Validation Recall')
            axes[1, 1].set_title('Model Recall')
            axes[1, 1].set_xlabel('Epoch')
            axes[1, 1].set_ylabel('Recall')
            axes[1, 1].legend()
            axes[1, 1].grid(True, alpha=0.3)
        
        plt.tight_layout()
        
        if save_path:
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
        plt.show()
    
    def generate_report(self, save_path: str = None) -> Dict:
        """Generate comprehensive evaluation report"""
        
        report = {
            'model_name': self.model_name,
            'evaluation_results': self.results,
            'summary': {}
        }
        
        # Summarize key metrics
        if 'classification' in self.results:
            class_results = self.results['classification']
            report['summary']['classification'] = {
                'accuracy': class_results['accuracy'],
                'weighted_f1': class_results['weighted_avg']['f1-score'],
                'weighted_precision': class_results['weighted_avg']['precision'],
                'weighted_recall': class_results['weighted_avg']['recall']
            }
            
            if 'roc_auc' in class_results:
                report['summary']['classification']['roc_auc'] = class_results['roc_auc']
        
        if 'anomaly_detection' in self.results:
            anomaly_results = self.results['anomaly_detection']
            report['summary']['anomaly_detection'] = {
                'precision': anomaly_results['precision'],
                'recall': anomaly_results['recall'],
                'f1_score': anomaly_results['f1_score'],
                'specificity': anomaly_results['specificity']
            }
            
            if 'roc_auc' in anomaly_results:
                report['summary']['anomaly_detection']['roc_auc'] = anomaly_results['roc_auc']
        
        # Save report
        if save_path:
            with open(save_path, 'w') as f:
                json.dump(report, f, indent=2)
        
        return report
    
    def print_summary(self):
        """Print evaluation summary"""
        print(f"\n{'='*50}")
        print(f"Model Evaluation Summary: {self.model_name}")
        print(f"{'='*50}")
        
        if 'classification' in self.results:
            class_results = self.results['classification']
            print(f"\nClassification Metrics:")
            print(f"  Accuracy: {class_results['accuracy']:.4f}")
            print(f"  Weighted F1: {class_results['weighted_avg']['f1-score']:.4f}")
            print(f"  Weighted Precision: {class_results['weighted_avg']['precision']:.4f}")
            print(f"  Weighted Recall: {class_results['weighted_avg']['recall']:.4f}")
            
            if 'roc_auc' in class_results:
                print(f"  ROC AUC: {class_results['roc_auc']:.4f}")
        
        if 'anomaly_detection' in self.results:
            anomaly_results = self.results['anomaly_detection']
            print(f"\nAnomaly Detection Metrics:")
            print(f"  Precision: {anomaly_results['precision']:.4f}")
            print(f"  Recall: {anomaly_results['recall']:.4f}")
            print(f"  F1 Score: {anomaly_results['f1_score']:.4f}")
            print(f"  Specificity: {anomaly_results['specificity']:.4f}")
            
            if 'roc_auc' in anomaly_results:
                print(f"  ROC AUC: {anomaly_results['roc_auc']:.4f}")

def benchmark_inference_speed(model, X_test: np.ndarray, num_runs: int = 100) -> Dict:
    """Benchmark model inference speed"""
    import time
    
    # Warm-up runs
    for _ in range(10):
        _ = model.predict(X_test[:1])
    
    # Single prediction timing
    single_times = []
    for _ in range(num_runs):
        start_time = time.time()
        _ = model.predict(X_test[:1])
        single_times.append((time.time() - start_time) * 1000)  # milliseconds
    
    # Batch prediction timing
    batch_times = []
    batch_sizes = [1, 10, 50, 100]
    
    for batch_size in batch_sizes:
        if batch_size <= len(X_test):
            batch_data = X_test[:batch_size]
            times = []
            
            for _ in range(num_runs // 10):  # Fewer runs for larger batches
                start_time = time.time()
                _ = model.predict(batch_data)
                times.append((time.time() - start_time) * 1000)
            
            batch_times.append({
                'batch_size': batch_size,
                'mean_time_ms': np.mean(times),
                'std_time_ms': np.std(times),
                'throughput_per_sec': batch_size / (np.mean(times) / 1000)
            })
    
    return {
        'single_prediction': {
            'mean_time_ms': np.mean(single_times),
            'std_time_ms': np.std(single_times),
            'min_time_ms': np.min(single_times),
            'max_time_ms': np.max(single_times),
            'p95_time_ms': np.percentile(single_times, 95)
        },
        'batch_predictions': batch_times
    }