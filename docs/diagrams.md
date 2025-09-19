# SentinelAI Architecture Diagrams

This document contains comprehensive Mermaid diagrams for the SentinelAI infrastructure, architecture, and data flow.

## 1. Complete Infrastructure Overview

```mermaid
graph TB
    subgraph "External Traffic"
        INT[Internet Traffic]
        LAN[Internal Network]
        IOT[IoT Devices]
    end
    
    subgraph "SentinelAI Infrastructure"
        subgraph "Container Orchestration"
            DC[Docker Compose]
            NET[sentinelai_network]
        end
        
        subgraph "Core Services"
            SENT[SentinelAI NGFW<br/>:8080, :9090]
            PROM[Prometheus<br/>:9091]
            GRAF[Grafana<br/>:3000]
            REDIS[Redis<br/>:6379]
        end
        
        subgraph "Data Storage"
            PD[(Prometheus Data)]
            GD[(Grafana Data)]
            SD[(SentinelAI Logs)]
            RD[(Redis Cache)]
        end
        
        subgraph "Configuration"
            PC[Prometheus Config]
            GC[Grafana Config]
            SC[SentinelAI Config]
            DB[Dashboard JSONs]
        end
    end
    
    subgraph "Monitoring & Alerting"
        DASH[Real-time Dashboards]
        ALERT[Alert Manager]
        NOTIF[Notifications]
    end
    
    subgraph "External Integrations"
        THREAT[Threat Intel Feeds]
        SOAR[SOAR Platform]
        SIEM[SIEM Integration]
    end
    
    %% Traffic Flow
    INT --> SENT
    LAN --> SENT
    IOT --> SENT
    
    %% Service Communications
    SENT -->|Metrics| PROM
    SENT -->|Cache| REDIS
    PROM -->|Data Source| GRAF
    
    %% Data Persistence
    SENT --> SD
    PROM --> PD
    GRAF --> GD
    REDIS --> RD
    
    %% Configuration Mounting
    PC --> PROM
    GC --> GRAF
    SC --> SENT
    DB --> GRAF
    
    %% Monitoring Flow
    GRAF --> DASH
    PROM --> ALERT
    ALERT --> NOTIF
    
    %% External Integrations
    THREAT --> SENT
    SENT --> SOAR
    SENT --> SIEM
    
    %% Container Orchestration
    DC -.-> SENT
    DC -.-> PROM
    DC -.-> GRAF
    DC -.-> REDIS
    NET -.-> SENT
    NET -.-> PROM
    NET -.-> GRAF
    NET -.-> REDIS
```

## 2. High-Level System Architecture

```mermaid
graph LR
    subgraph "Traffic Sources"
        EXT[External Traffic<br/>40+ Gbps]
        INT[Internal Network]
        EDGE[Edge Devices]
    end
    
    subgraph "SentinelAI Core"
        CAP[Packet Capture<br/>gopacket]
        PROC[Traffic Processing<br/>1M+ pps]
        AI[AI Engine<br/>CNN/RNN Models]
        POL[Policy Engine<br/>Zero Trust]
    end
    
    subgraph "Response Actions"
        ALLOW[Allow Traffic]
        BLOCK[Block & Drop]
        QUAR[Quarantine]
        ALERT[Generate Alert]
    end
    
    subgraph "Analytics & Learning"
        ML[ML Training<br/>TensorFlow]
        ANOM[Anomaly Detection<br/>Isolation Forest]
        FED[Federated Learning<br/>Privacy Preserving]
    end
    
    subgraph "Monitoring Stack"
        METRICS[Prometheus Metrics]
        VIZ[Grafana Dashboards]
        LOG[Centralized Logging]
    end
    
    %% Main Flow
    EXT --> CAP
    INT --> CAP
    EDGE --> CAP
    
    CAP --> PROC
    PROC --> AI
    AI --> POL
    
    POL --> ALLOW
    POL --> BLOCK
    POL --> QUAR
    POL --> ALERT
    
    %% Analytics Flow
    PROC --> ML
    AI --> ANOM
    ML --> FED
    
    %% Monitoring Flow
    CAP --> METRICS
    PROC --> METRICS
    AI --> METRICS
    POL --> METRICS
    
    METRICS --> VIZ
    PROC --> LOG
    
    %% Feedback Loop
    FED -.-> AI
    ANOM -.-> POL
```

## 3. Detailed Component Architecture

```mermaid
graph TB
    subgraph "Network Layer"
        PKT[Packet Capture<br/>gopacket/libpcap]
        RAW[Raw Packets]
        BPF[BPF Filters]
    end
    
    subgraph "Feature Extraction Layer"
        TLS[TLS Metadata<br/>JA3/JA3S]
        STAT[Statistical Features<br/>50+ metrics]
        FLOW[Flow Tracking<br/>100K+ flows]
        META[Protocol Analysis]
    end
    
    subgraph "AI/ML Layer"
        CNN[CNN Models<br/>Traffic Classification]
        RNN[RNN Models<br/>Sequence Analysis]
        ISO[Isolation Forest<br/>Anomaly Detection]
        DBS[DBSCAN<br/>Clustering]
        ONNX[ONNX Runtime<br/>Model Inference]
    end
    
    subgraph "Decision Layer"
        RISK[Risk Assessment<br/>Score Calculation]
        ZT[Zero Trust Engine<br/>Identity Based]
        RULES[Policy Rules<br/>Dynamic Updates]
        EVAL[Rule Evaluation<br/><100ms]
    end
    
    subgraph "Action Layer"
        EXEC[Action Executor]
        IPTABLES[iptables/netfilter]
        NOTIFY[Notification System]
        AUDIT[Audit Logging]
    end
    
    subgraph "Data Layer"
        CACHE[Redis Cache<br/>Session Data]
        TSDB[Time Series DB<br/>Prometheus]
        LOGS[Log Storage<br/>Structured Logs]
        MODELS[Model Storage<br/>Versioned]
    end
    
    subgraph "Management Layer"
        API[RESTful API<br/>:8080]
        METRICS_EP[Metrics Endpoint<br/>:9090]
        CONFIG[Configuration<br/>Hot Reload]
        HEALTH[Health Checks]
    end
    
    %% Data Flow
    RAW --> PKT
    PKT --> BPF
    BPF --> TLS
    BPF --> STAT
    BPF --> FLOW
    BPF --> META
    
    TLS --> CNN
    STAT --> RNN
    FLOW --> ISO
    META --> DBS
    
    CNN --> ONNX
    RNN --> ONNX
    ISO --> ONNX
    DBS --> ONNX
    
    ONNX --> RISK
    RISK --> ZT
    ZT --> RULES
    RULES --> EVAL
    
    EVAL --> EXEC
    EXEC --> IPTABLES
    EXEC --> NOTIFY
    EXEC --> AUDIT
    
    %% Data Storage
    FLOW --> CACHE
    STAT --> TSDB
    AUDIT --> LOGS
    CNN --> MODELS
    
    %% Management
    EXEC --> API
    PKT --> METRICS_EP
    API --> CONFIG
    CONFIG --> HEALTH
```

## 4. Data Flow Architecture

```mermaid
sequenceDiagram
    participant N as Network Traffic
    participant C as Packet Capture
    participant F as Feature Extraction
    participant A as AI Engine
    participant P as Policy Engine
    participant R as Response Actions
    participant M as Monitoring
    
    N->>C: Raw Packets (40+ Gbps)
    C->>F: Captured Packets
    
    Note over F: Extract 50+ Features
    F->>F: TLS Metadata (JA3/JA3S)
    F->>F: Statistical Analysis
    F->>F: Flow Tracking
    
    F->>A: Feature Vector
    
    Note over A: ML Inference (<1ms)
    A->>A: CNN Classification
    A->>A: Anomaly Detection
    A->>A: Risk Scoring
    
    A->>P: Threat Score + Context
    
    Note over P: Policy Evaluation
    P->>P: Zero Trust Check
    P->>P: Rule Matching
    P->>P: Action Decision
    
    P->>R: Action Command
    
    alt Allow Traffic
        R->>N: Forward Packet
    else Block Traffic
        R->>N: Drop Packet
        R->>M: Log Block Action
    else Quarantine
        R->>R: Isolate Session
        R->>M: Alert Generation
    end
    
    Note over M: Real-time Metrics
    C->>M: Performance Metrics
    A->>M: ML Metrics
    P->>M: Policy Metrics
    R->>M: Action Metrics
```

## 5. ML Pipeline Architecture

```mermaid
graph TB
    subgraph "Training Pipeline"
        DATA[Training Data<br/>NSL-KDD, CICIDS2017]
        PREP[Data Preprocessing<br/>Normalization]
        SPLIT[Train/Test Split<br/>80/20]
        TRAIN[Model Training<br/>TensorFlow/PyTorch]
        VAL[Model Validation<br/>Cross-validation]
        EXPORT[Model Export<br/>ONNX Format]
    end
    
    subgraph "Inference Pipeline"
        STREAM[Live Traffic Stream]
        FEAT[Feature Engineering<br/>Real-time]
        BATCH[Micro-batching<br/>Optimization]
        INF[Model Inference<br/>ONNX Runtime]
        POST[Post-processing<br/>Score Normalization]
    end
    
    subgraph "Model Management"
        REG[Model Registry<br/>Versioning]
        DEPLOY[Model Deployment<br/>Hot Swap]
        MONITOR[Model Monitoring<br/>Drift Detection]
        UPDATE[Model Updates<br/>A/B Testing]
    end
    
    subgraph "Federated Learning"
        LOCAL[Local Training<br/>Privacy Preserving]
        AGG[Model Aggregation<br/>Secure Aggregation]
        GLOBAL[Global Model<br/>Collaborative]
        DIST[Model Distribution<br/>Delta Updates]
    end
    
    %% Training Flow
    DATA --> PREP
    PREP --> SPLIT
    SPLIT --> TRAIN
    TRAIN --> VAL
    VAL --> EXPORT
    
    %% Inference Flow
    STREAM --> FEAT
    FEAT --> BATCH
    BATCH --> INF
    INF --> POST
    
    %% Model Management
    EXPORT --> REG
    REG --> DEPLOY
    DEPLOY --> INF
    INF --> MONITOR
    MONITOR --> UPDATE
    
    %% Federated Learning
    TRAIN --> LOCAL
    LOCAL --> AGG
    AGG --> GLOBAL
    GLOBAL --> DIST
    DIST --> DEPLOY
    
    %% Feedback Loops
    POST -.-> MONITOR
    UPDATE -.-> TRAIN
```

## 6. Monitoring and Observability Architecture

```mermaid
graph TB
    subgraph "Metrics Collection"
        APP[Application Metrics<br/>Custom Metrics]
        SYS[System Metrics<br/>CPU, Memory, Network]
        ML_M[ML Metrics<br/>Accuracy, Latency]
        SEC[Security Metrics<br/>Threats, Blocks]
    end
    
    subgraph "Prometheus Stack"
        PROM[Prometheus Server<br/>Scraping & Storage]
        ALERT[AlertManager<br/>Rule Evaluation]
        PUSH[Pushgateway<br/>Batch Jobs]
        RULES[Alert Rules<br/>YAML Config]
    end
    
    subgraph "Visualization Layer"
        GRAF[Grafana Dashboards]
        OVER[Overview Dashboard<br/>System Health]
        SEC_D[Security Dashboard<br/>Threat Analysis]
        PERF[Performance Dashboard<br/>ML Metrics]
        CUSTOM[Custom Dashboards<br/>Business KPIs]
    end
    
    subgraph "Alerting & Notifications"
        SLACK[Slack Integration]
        EMAIL[Email Notifications]
        WEBHOOK[Webhook Endpoints]
        PAGER[PagerDuty Integration]
    end
    
    subgraph "Log Management"
        LOGS[Application Logs<br/>Structured JSON]
        AUDIT[Audit Logs<br/>Security Events]
        ACCESS[Access Logs<br/>API Requests]
        ERROR[Error Logs<br/>Stack Traces]
    end
    
    %% Metrics Flow
    APP --> PROM
    SYS --> PROM
    ML_M --> PROM
    SEC --> PROM
    
    %% Prometheus Processing
    PROM --> ALERT
    PROM --> GRAF
    RULES --> ALERT
    
    %% Dashboard Creation
    PROM --> OVER
    PROM --> SEC_D
    PROM --> PERF
    PROM --> CUSTOM
    
    %% Alerting Flow
    ALERT --> SLACK
    ALERT --> EMAIL
    ALERT --> WEBHOOK
    ALERT --> PAGER
    
    %% Log Aggregation
    LOGS --> GRAF
    AUDIT --> SEC_D
    ACCESS --> PERF
    ERROR --> ALERT
```

## 7. Deployment Architecture

```mermaid
graph TB
    subgraph "Development Environment"
        DEV[Developer Workstation]
        LINT[Code Linting<br/>golangci-lint]
        TEST[Unit Tests<br/>Go testing]
        BUILD[Local Build<br/>go build]
    end
    
    subgraph "CI/CD Pipeline"
        GIT[Git Repository<br/>GitHub]
        CI[GitHub Actions<br/>Automated Testing]
        SCAN[Security Scanning<br/>Vulnerability Check]
        DOCKER[Docker Build<br/>Multi-stage]
        REG[Container Registry<br/>Docker Hub]
    end
    
    subgraph "Staging Environment"
        STAGE[Staging Cluster<br/>Docker Compose]
        INT_TEST[Integration Tests<br/>End-to-end]
        PERF_TEST[Performance Tests<br/>Load Testing]
        SEC_TEST[Security Tests<br/>Penetration Testing]
    end
    
    subgraph "Production Environment"
        PROD[Production Cluster]
        LB[Load Balancer<br/>HAProxy/NGINX]
        SENT_PROD[SentinelAI Instances<br/>High Availability]
        MON_PROD[Monitoring Stack<br/>Prometheus/Grafana]
        BACKUP[Backup Systems<br/>Data Protection]
    end
    
    subgraph "Infrastructure"
        K8S[Kubernetes Cluster<br/>Container Orchestration]
        HELM[Helm Charts<br/>Package Management]
        ISTIO[Service Mesh<br/>Traffic Management]
        STORAGE[Persistent Storage<br/>Data Persistence]
    end
    
    %% Development Flow
    DEV --> LINT
    LINT --> TEST
    TEST --> BUILD
    BUILD --> GIT
    
    %% CI/CD Flow
    GIT --> CI
    CI --> SCAN
    SCAN --> DOCKER
    DOCKER --> REG
    
    %% Staging Flow
    REG --> STAGE
    STAGE --> INT_TEST
    INT_TEST --> PERF_TEST
    PERF_TEST --> SEC_TEST
    
    %% Production Flow
    SEC_TEST --> PROD
    PROD --> LB
    LB --> SENT_PROD
    SENT_PROD --> MON_PROD
    MON_PROD --> BACKUP
    
    %% Infrastructure
    PROD --> K8S
    K8S --> HELM
    HELM --> ISTIO
    ISTIO --> STORAGE
```

## 8. Security Architecture

```mermaid
graph TB
    subgraph "Network Security"
        FW[Perimeter Firewall]
        IDS[Intrusion Detection]
        WAF[Web Application Firewall]
        DPI[Deep Packet Inspection]
    end
    
    subgraph "Zero Trust Components"
        IDENTITY[Identity Provider<br/>OAuth2/OIDC]
        MFA[Multi-Factor Auth<br/>TOTP/FIDO2]
        RBAC[Role-Based Access<br/>Permissions]
        POLICY[Policy Decision Point<br/>XACML]
    end
    
    subgraph "SentinelAI Security"
        TLS_TERM[TLS Termination<br/>Certificate Management]
        ENCRYPT[Data Encryption<br/>AES-256]
        SIGN[Code Signing<br/>Digital Signatures]
        VAULT[Secret Management<br/>HashiCorp Vault]
    end
    
    subgraph "Monitoring & Compliance"
        SIEM_INT[SIEM Integration<br/>Event Correlation]
        AUDIT_LOG[Audit Logging<br/>Tamper-proof]
        COMPLIANCE[Compliance Framework<br/>NIST/SOC2]
        FORENSICS[Digital Forensics<br/>Evidence Collection]
    end
    
    subgraph "Threat Intelligence"
        IOC[Indicators of Compromise<br/>STIX/TAXII]
        FEED[Threat Feeds<br/>Commercial/Open]
        INTEL[Threat Intelligence<br/>Contextual Analysis]
        SHARING[Information Sharing<br/>Community]
    end
    
    %% Security Flow
    FW --> SentinelAI
    IDS --> SentinelAI
    WAF --> SentinelAI
    DPI --> SentinelAI
    
    %% Zero Trust Flow
    IDENTITY --> MFA
    MFA --> RBAC
    RBAC --> POLICY
    POLICY --> SentinelAI
    
    %% Internal Security
    TLS_TERM --> SentinelAI
    ENCRYPT --> SentinelAI
    SIGN --> SentinelAI
    VAULT --> SentinelAI
    
    %% Monitoring Integration
    SentinelAI --> SIEM_INT
    SentinelAI --> AUDIT_LOG
    AUDIT_LOG --> COMPLIANCE
    SIEM_INT --> FORENSICS
    
    %% Threat Intelligence
    IOC --> FEED
    FEED --> INTEL
    INTEL --> SentinelAI
    SentinelAI --> SHARING
```

## 9. Container Network Architecture

```mermaid
graph TB
    subgraph "Host Network Interface"
        ETH0[eth0 - External Interface]
        ETH1[eth1 - Internal Interface]
        DOCKER0[docker0 - Bridge Interface]
    end
    
    subgraph "Docker Network: sentinelai_network"
        subgraph "SentinelAI Container"
            SENT_NET[Network: 172.20.0.10<br/>Ports: 8080, 9090]
            SENT_CAP[CAP_NET_ADMIN<br/>CAP_NET_RAW]
        end
        
        subgraph "Prometheus Container"
            PROM_NET[Network: 172.20.0.11<br/>Port: 9090]
        end
        
        subgraph "Grafana Container"
            GRAF_NET[Network: 172.20.0.12<br/>Port: 3000]
        end
        
        subgraph "Redis Container"
            REDIS_NET[Network: 172.20.0.13<br/>Port: 6379]
        end
    end
    
    subgraph "Port Mappings"
        HOST_8080[Host:8080] --> SENT_8080[Container:8080]
        HOST_9090[Host:9090] --> SENT_9090[Container:9090]
        HOST_9091[Host:9091] --> PROM_9090[Container:9090]
        HOST_3000[Host:3000] --> GRAF_3000[Container:3000]
        HOST_6379[Host:6379] --> REDIS_6379[Container:6379]
    end
    
    subgraph "Volume Mounts"
        CONFIG_VOL[./configs:/app/configs]
        MODELS_VOL[./models:/app/models]
        LOGS_VOL[sentinelai_logs:/app/logs]
        PROM_VOL[prometheus_data:/prometheus]
        GRAF_VOL[grafana_data:/var/lib/grafana]
    end
    
    %% Network Connections
    ETH0 --> SENT_NET
    ETH1 --> SENT_NET
    
    %% Inter-container Communication
    SENT_NET <--> PROM_NET
    SENT_NET <--> REDIS_NET
    PROM_NET <--> GRAF_NET
    
    %% Volume Mounting
    CONFIG_VOL --> SENT_NET
    MODELS_VOL --> SENT_NET
    LOGS_VOL --> SENT_NET
    PROM_VOL --> PROM_NET
    GRAF_VOL --> GRAF_NET
```

These comprehensive Mermaid diagrams provide detailed visualizations of your SentinelAI infrastructure from multiple perspectives, including overall architecture, component interactions, data flows, and deployment strategies. You can use these diagrams in documentation, presentations, or planning sessions.