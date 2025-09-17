# SentinelAI ML Training Requirements

## Python Dependencies
```bash
pip install -r requirements.txt
```

## Required Packages
- tensorflow>=2.8.0
- scikit-learn>=1.0.0
- pandas>=1.3.0
- numpy>=1.21.0
- matplotlib>=3.5.0
- seaborn>=0.11.0
- requests>=2.27.0
- tqdm>=4.62.0
- jupyter>=1.0.0
- onnx>=1.12.0
- tf2onnx>=1.9.0
- PyYAML>=6.0

## Dataset Setup

### Automated Setup
```bash
# Setup training environment
python scripts/datasets/setup_training.py

# List available datasets
python scripts/datasets/download_datasets.py list

# Download all datasets
python scripts/datasets/download_datasets.py download --all

# Check dataset status
python scripts/datasets/download_datasets.py check
```

### Manual Dataset Downloads

For datasets requiring manual download:

1. **UNSW-NB15**: Visit https://research.unsw.edu.au/projects/unsw-nb15-dataset
2. **CICIDS2017**: Visit https://www.unb.ca/cic/datasets/ids-2017.html
3. **CTU-13**: Visit https://www.stratosphereips.org/datasets-ctu13

Place downloaded files in the appropriate `datasets/raw/` subdirectories.

## Training Models

```bash
# Train all models
python ml-training/train_models.py

# Or explore in Jupyter
jupyter notebook ml-training/notebooks/quick_start.ipynb
```