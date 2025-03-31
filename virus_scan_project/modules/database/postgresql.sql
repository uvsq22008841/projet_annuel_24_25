-- Création de tables pour stocker les résultats d'analyse détaillés

-- Table des analyses statiques de fichiers
CREATE TABLE file_static_analyses (
    analysis_id SERIAL PRIMARY KEY,
    file_id INTEGER NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    analysis_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    mime_type VARCHAR(100),
    analysis_result JSONB NOT NULL,
    risk_score FLOAT,
    risk_level VARCHAR(20),
    risk_factors JSONB
);

-- Table des analyses comportementales
CREATE TABLE file_sandbox_analyses (
    analysis_id SERIAL PRIMARY KEY,
    file_id INTEGER NOT NULL REFERENCES files(file_id) ON DELETE CASCADE,
    analysis_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    execution_success BOOLEAN,
    execution_output TEXT,
    processes_created JSONB,
    file_operations JSONB,
    network_connections JSONB,
    analysis_result JSONB NOT NULL,
    risk_score FLOAT,
    risk_level VARCHAR(20),
    risk_factors JSONB
);

-- Table des analyses détaillées d'URL
CREATE TABLE url_detailed_analyses (
    analysis_id SERIAL PRIMARY KEY,
    url_id INTEGER NOT NULL REFERENCES urls(url_id) ON DELETE CASCADE,
    analysis_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    url_structure JSONB,
    dns_info JSONB,
    certificate_info JSONB,
    content_info JSONB,
    phishing_analysis JSONB,
    malware_analysis JSONB,
    risk_score FLOAT,
    risk_level VARCHAR(20),
    risk_factors JSONB
);

-- Table des analyses détaillées d'IP
CREATE TABLE ip_detailed_analyses (
    analysis_id SERIAL PRIMARY KEY,
    ip_id INTEGER NOT NULL REFERENCES ip_addresses(ip_id) ON DELETE CASCADE,
    analysis_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reverse_dns VARCHAR(255),
    geolocation JSONB,
    asn_info JSONB,
    port_scan JSONB,
    reputation JSONB,
    risk_score FLOAT,
    risk_level VARCHAR(20),
    risk_factors JSONB
);

-- Table des signatures de malware
CREATE TABLE malware_signatures (
    signature_id SERIAL PRIMARY KEY,
    hash_type VARCHAR(10) NOT NULL,
    hash_value VARCHAR(64) NOT NULL,
    malware_name VARCHAR(100),
    malware_type VARCHAR(50),
    severity VARCHAR(20),
    description TEXT,
    added_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_date TIMESTAMP,
    detection_count INTEGER DEFAULT 0
);

-- Table des signatures à base de motifs
CREATE TABLE pattern_signatures (
    signature_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    content_type VARCHAR(50) NOT NULL,
    pattern TEXT NOT NULL,
    severity VARCHAR(20),
    category VARCHAR(50),
    description TEXT,
    added_date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_date TIMESTAMP,
    detection_count INTEGER DEFAULT 0
);

-- Vue pour afficher les résultats d'analyse
CREATE VIEW analysis_results_view AS
SELECT 
    'file' AS entity_type,
    f.file_id AS entity_id,
    f.file_name AS entity_name,
    f.upload_date AS submission_date,
    u.username AS submitter,
    COALESCE(fsa.risk_level, fba.risk_level, 'Inconnu') AS risk_level,
    GREATEST(COALESCE(fsa.risk_score, 0), COALESCE(fba.risk_score, 0)) AS risk_score,
    COALESCE(fsa.analysis_date, fba.analysis_date) AS last_analysis_date
FROM 
    files f
LEFT JOIN 
    file_static_analyses fsa ON f.file_id = fsa.file_id
LEFT JOIN 
    file_sandbox_analyses fba ON f.file_id = fba.file_id
JOIN 
    users u ON f.submitter_id = u.user_id

UNION ALL

SELECT 
    'url' AS entity_type,
    url.url_id AS entity_id,
    url.url AS entity_name,
    url.submit_date AS submission_date,
    u.username AS submitter,
    uda.risk_level,
    uda.risk_score,
    uda.analysis_date AS last_analysis_date
FROM 
    urls url
LEFT JOIN 
    url_detailed_analyses uda ON url.url_id = uda.url_id
JOIN 
    users u ON url.submitter_id = u.user_id

UNION ALL

SELECT 
    'ip' AS entity_type,
    ip.ip_id AS entity_id,
    ip.ip_address AS entity_name,
    ip.submit_date AS submission_date,
    u.username AS submitter,
    ida.risk_level,
    ida.risk_score,
    ida.analysis_date AS last_analysis_date
FROM 
    ip_addresses ip
LEFT JOIN 
    ip_detailed_analyses ida ON ip.ip_id = ida.ip_id
JOIN 
    users u ON ip.submitter_id = u.user_id;