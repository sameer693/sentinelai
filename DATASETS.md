# SentinelAI Dataset Recommendations

## Overview
SentinelAI requires diverse, high-quality cybersecurity datasets for training its AI models. This document outlines the recommended datasets, storage strategies, and training approaches for Phase 2 development.

## Recommended Datasets

### 1. Network Traffic Datasets (Primary)

#### UNSW-NB15 Dataset ⭐
- **Purpose**: Multi-class network intrusion detection
- **Size**: ~2.5 million network flow records
- **Features**: 49 features including flow duration, packet counts, protocols
- **Labels**: 10 attack categories (Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms, Normal)
- **Download**: [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset)
- **Storage**: External download (2.1GB)

#### CICIDS2017 Dataset ⭐
- **Purpose**: Comprehensive network intrusion detection
- **Size**: ~2.8 million flows over 5 days
- **Features**: 80+ features from packet-level analysis
- **Labels**: 15 attack categories including DDoS, PortScan, Brute Force, Web attacks
- **Download**: [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html)
- **Storage**: External download (4.3GB)

#### CICIDS2018 Dataset
- **Purpose**: Advanced persistent threats and botnet detection
- **Size**: 16 million flows
- **Features**: Enhanced feature set with behavioral analysis
- **Labels**: 14 attack categories including Botnet, Infiltration, Web attacks
- **Download**: [CICIDS2018](https://www.unb.ca/cic/datasets/ids-2018.html)
- **Storage**: External download (7.8GB)

### 2. Malware & TLS Datasets

#### MalwareCaptures Project
- **Purpose**: Real malware network traces
- **Size**: 300+ PCAP files
- **Features**: Raw packet captures with malware behavior
- **Labels**: Malware family classification
- **Download**: [MalwareCaptures](https://mcfp.weebly.com/the-malware-capture-facility-project.html)
- **Storage**: External download (varies by scenario)

#### TLS-Fingerprinting Dataset
- **Purpose**: Encrypted traffic classification
- **Size**: 100K+ TLS handshakes
- **Features**: JA3/JA3S fingerprints, cipher suites, extensions
- **Labels**: Application classification (browsers, malware, etc.)
- **Custom**: Create from live captures
- **Storage**: External collection

### 3. Specialized Security Datasets

#### CTU-13 Botnet Dataset
- **Purpose**: Botnet detection and analysis
- **Size**: 13 different botnet scenarios
- **Features**: Network flows with botnet C&C communication
- **Labels**: Normal vs. Botnet traffic
- **Download**: [CTU-13](https://www.stratosphereips.org/datasets-ctu13)
- **Storage**: External download (500MB)

#### EMBER Malware Dataset
- **Purpose**: Static malware analysis (PE files)
- **Size**: 1.1 million PE files
- **Features**: 2,381 raw features from PE structure
- **Labels**: Malware vs. Benign classification
- **Download**: [EMBER](https://github.com/elastic/ember)
- **Storage**: External download (5.4GB)

## Storage Strategy

### ❌ NOT in GitHub Repository
**Reasons to avoid storing datasets in repo:**
- Large file sizes (GBs) exceed GitHub limits
- Legal/licensing concerns with redistribution
- Repository bloat and slow clones
- Bandwidth costs for users
- Version control inefficiency

### ✅ Recommended Approach

#### 1. External Dataset Management
```bash
# Create datasets directory (gitignored)
mkdir datasets/
echo "datasets/" >> .gitignore

# Add download scripts instead
mkdir scripts/datasets/
```

#### 2. Download Scripts
Create automated download and verification scripts:

```python
# scripts/datasets/download_datasets.py
"""
Automated dataset downloader for SentinelAI
Downloads, verifies, and prepares training datasets
"""

DATASETS = {
    'unsw_nb15': {
        'url': 'https://cloudstor.aarnet.edu.au/plus/...',
        'checksum': 'sha256:abc123...',
        'size': '2.1GB',
        'files': ['UNSW_NB15_training-set.csv', 'UNSW_NB15_testing-set.csv']
    },
    'cicids2017': {
        'url': 'https://www.unb.ca/cic/datasets/ids-2017.html',
        'checksum': 'sha256:def456...',
        'size': '4.3GB',
        'files': ['Monday-WorkingHours.pcap_ISCX.csv', ...]
    }
}
```

#### 3. Dataset Configuration
```yaml
# configs/datasets.yaml
datasets:
  unsw_nb15:
    path: "./datasets/UNSW_NB15_training-set.csv"
    features: 49
    samples: 2540044
    classes: 10
    
  cicids2017:
    path: "./datasets/CICIDS2017/"
    features: 80
    samples: 2830743
    classes: 15
```

#### 4. Cloud Storage Options
- **Kaggle Datasets**: Host cleaned versions
- **Google Drive**: Share links for team access
- **AWS S3**: Scalable storage with access controls
- **Academic Repositories**: Cite original sources

## Training Strategy

### Phase 2A: Foundation Models (Weeks 1-2)
```python
# Start with smaller, clean datasets
1. UNSW-NB15 (filtered subset)
2. CTU-13 (botnet scenarios)
3. Synthetic data generation
```

### Phase 2B: Advanced Models (Weeks 3-4)
```python
# Scale to larger, comprehensive datasets
1. Full CICIDS2017/2018
2. TLS fingerprinting data
3. Cross-validation with multiple datasets
```

### Phase 2C: Production Models (Weeks 5-6)
```python
# Real-world validation and fine-tuning
1. Live traffic validation
2. Adversarial training
3. Model ensemble techniques
```

## Implementation Plan

### 1. Dataset Preparation Structure
```
ml-training/
├── datasets/               # Gitignored
│   ├── raw/               # Original downloaded files
│   ├── processed/         # Cleaned and preprocessed
│   └── synthetic/         # Generated data
├── scripts/
│   ├── download_datasets.py
│   ├── preprocess_data.py
│   └── validate_datasets.py
├── configs/
│   └── datasets.yaml
└── notebooks/             # Jupyter notebooks for exploration
    ├── data_exploration.ipynb
    └── feature_analysis.ipynb
```

### 2. Updated Training Pipeline
```python
# Enhanced train_models.py
class DatasetManager:
    def __init__(self):
        self.download_manager = DatasetDownloader()
        self.validator = DatasetValidator()
        
    def prepare_datasets(self):
        # Download if missing
        # Validate checksums
        # Preprocess and cache
        # Return ready-to-use data
```

### 3. Automated Workflow
```bash
# Single command setup
python scripts/setup_training.py
# - Downloads required datasets
# - Validates integrity
# - Preprocesses data
# - Trains initial models
# Setup (one-time)
python scripts/datasets/setup_training.py

# Generate synthetic data
python scripts/datasets/download_datasets.py generate --synthetic --samples 50000

# Train models  
python scripts/datasets/quick_train.py

# Check status
python scripts/datasets/download_datasets.py check
```

## Legal and Ethical Considerations

### Dataset Licensing
- ✅ Academic datasets: Usually free for research
- ✅ UNSW-NB15: Academic license required
- ✅ CICIDS: Free for academic/research use
- ⚠️ Commercial use: Check licensing terms

### Privacy and Compliance
- Anonymized datasets only
- No personally identifiable information
- Compliance with institutional policies
- Proper attribution and citations

## Getting Started

### Quick Setup
1. Clone repository (datasets excluded)
2. Run `python scripts/setup_training.py`
3. Configure dataset paths in `configs/datasets.yaml`
4. Start training with `python ml-training/train_models.py`

### Manual Setup
1. Download datasets from official sources
2. Place in `datasets/` directory
3. Update configuration files
4. Run preprocessing scripts

This approach ensures:
- ✅ Legal compliance with dataset licensing
- ✅ Efficient repository management
- ✅ Scalable training infrastructure
- ✅ Reproducible research methodology
- ✅ Team collaboration without data duplication
