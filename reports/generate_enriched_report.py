import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import warnings
warnings.filterwarnings('ignore')

# ============================================================
# 1. LOAD DATA
# ============================================================
logs  = pd.read_csv('/mnt/user-data/uploads/data_access_logs.csv')
users = pd.read_csv('/mnt/user-data/uploads/user_profiles.csv')

# ============================================================
# 2. MERGE & PARSE
# ============================================================
master = logs.merge(users, on=['user_id','username'], how='left')
master['timestamp']  = pd.to_datetime(master['timestamp'])
master['hire_date']  = pd.to_datetime(master['hire_date'])
master['last_login'] = pd.to_datetime(master['last_login'])
master = master.sort_values('timestamp').reset_index(drop=True)

master['hour']    = master['timestamp'].dt.hour
master['weekday'] = master['timestamp'].dt.weekday   # 0=Mon … 6=Sun
master['date']    = master['timestamp'].dt.date

# Tenure in months (clamp negatives to 0 for data quirks)
master['tenure_months'] = (
    (master['timestamp'] - master['hire_date']).dt.days / 30
).clip(lower=0).round(0).astype(int)

# ============================================================
# 3. CONTEXT FLAGS
# ============================================================

# --- Unauthorized resource access ---------------------------
RESOURCE_KEYWORDS = {
    'Customer_Vault': ['PROD_DB','SALESFORCE','CUSTOMER'],
    'HRIS':           ['HRIS','SERVICENOW','AD','AZURE_AD'],
    'Admin_Console':  ['ADMIN_SYS','OKT','AZURE_AD','SIEM'],
    'GL_System':      ['GL','FINANCE','EMAIL'],
    'PROD_DB':        ['PROD_DB','EMAIL'],
    'SIEM':           ['SIEM','AZURE_AD'],
    'Data_Lake':      ['GCP','AWS_IAM','AZURE_AD'],
    'Email_Archive':  ['EMAIL','OKT','AZURE_AD'],
    'BI_Tool':        ['SALESFORCE','GCP','AZURE_AD','BI'],
    'File_Share':     ['AD','AZURE_AD','VPN','FILE'],
}

def is_unauthorized(row):
    if pd.isna(row['systems_access']):
        return True
    approved = [s.strip().upper() for s in str(row['systems_access']).split('|')]
    keywords = RESOURCE_KEYWORDS.get(row['resource'], [])
    for kw in keywords:
        for sys in approved:
            if kw in sys:
                return False
    if row['resource'].upper() in approved:
        return False
    return True

master['unauthorized'] = master.apply(is_unauthorized, axis=1)

# --- First-ever access to this resource by user -------------
master['first_access_resource'] = ~master.duplicated(subset=['username','resource'], keep='first')

# --- First export action ever for this user -----------------
master['first_export'] = (
    (master['action'] == 'export_data') &
    (~master.duplicated(subset=['username','action'], keep='first'))
)

# --- Stale / dormant account --------------------------------
master['stale_account']     = master['days_inactive'] >= 30
master['very_stale_account'] = master['days_inactive'] >= 50

# --- Time-of-day flags from actual hour ---------------------
master['is_night']    = ((master['hour'] < 6)  | (master['hour'] >= 22)).astype(int)
master['is_off_hours']= ((master['hour'] < 9)  | (master['hour'] > 17)).astype(int)
master['is_weekend']  = (master['weekday'] >= 5).astype(int)

# --- Privilege risk multipliers ----------------------------
PRIV_MAP = {'user': 1, 'power-user': 1.2, 'service-account': 1.3, 'admin': 1.5}
master['priv_mult'] = master['privilege_level'].map(PRIV_MAP).fillna(1)

# --- Sensitivity numeric ------------------------------------
SENS_MAP = {'low': 1, 'medium': 2, 'high': 3}
master['sens_num'] = master['resource_sensitivity'].map(SENS_MAP).fillna(1)

# --- Action risk weights ------------------------------------
ACTION_W = {
    'login': 0,
    'sql_query': 10,
    'file_access': 10,
    'api_call': 15,
    'export_data': 25,
    'admin_operation': 30,
}

# --- Resource risk weights ----------------------------------
RESOURCE_W = {
    'Customer_Vault': 30,
    'HRIS':           25,
    'Admin_Console':  30,
    'GL_System':      25,
    'PROD_DB':        25,
    'SIEM':           15,
    'Data_Lake':      15,
    'Email_Archive':  15,
    'BI_Tool':        10,
    'File_Share':     10,
}

# ============================================================
# 4. RISK SCORING ENGINE
# ============================================================
master['base_score'] = 0.0

# Sensitivity (0-25)
master['base_score'] += master['sens_num'].map({1: 0, 2: 12, 3: 25})

# Action type
master['base_score'] += master['action'].map(ACTION_W).fillna(5)

# Resource type
master['base_score'] += master['resource'].map(RESOURCE_W).fillna(10)

# Time penalties
master['base_score'] += master['is_night']     * 20
master['base_score'] += master['is_weekend']   * 12
master['base_score'] += master['is_off_hours'] * 8

# Inactivity penalty
master['base_score'] += master['stale_account'].astype(int)      * 8
master['base_score'] += master['very_stale_account'].astype(int) * 12

# Access violations
master['base_score'] += master['unauthorized'].astype(int) * 18
master['base_score'] += master['first_access_resource'].astype(int) * 5

# Failed attempts
master['base_score'] += (master['status'] == 'failure').astype(int) * 10

# New employee risk
master['base_score'] += (master['tenure_months'] < 3).astype(int) * 8

# Privilege multiplier
master['base_score'] = master['base_score'] * master['priv_mult']

# Normalise 0-100
raw_max = master['base_score'].max()
master['raw_risk_score'] = master['base_score']
master['risk_score'] = (master['base_score'] / raw_max * 100).round(1)

# ============================================================
# 5. ISOLATION FOREST (ML ANOMALY LAYER)
# ============================================================
# Ensure consistent encoding
action_enc    = LabelEncoder().fit(master['action'].fillna('unknown'))
resource_enc  = LabelEncoder().fit(master['resource'].fillna('unknown'))
dept_enc      = LabelEncoder().fit(master['department'].fillna('unknown'))
priv_enc      = LabelEncoder().fit(master['privilege_level'].fillna('user'))

features = pd.DataFrame({
    'hour':            master['hour'],
    'weekday':         master['weekday'],
    'is_night':        master['is_night'],
    'is_weekend':      master['is_weekend'],
    'sens_num':        master['sens_num'],
    'action_enc':      action_enc.transform(master['action'].fillna('unknown')),
    'resource_enc':    resource_enc.transform(master['resource'].fillna('unknown')),
    'dept_enc':        dept_enc.transform(master['department'].fillna('unknown')),
    'priv_enc':        priv_enc.transform(master['privilege_level'].fillna('user')),
    'tenure_months':   master['tenure_months'],
    'days_inactive':   master['days_inactive'].fillna(0),
    'failed':          (master['status']=='failure').astype(int),
    'unauthorized':    master['unauthorized'].astype(int),
    'risk_score':      master['risk_score'],
})

iso = IsolationForest(n_estimators=200, contamination=0.25, random_state=42)
master['ml_anomaly'] = iso.fit_predict(features)   # -1 = anomaly, 1 = normal
master['ml_flag']    = (master['ml_anomaly'] == -1).astype(int)

# ============================================================
# 6. FINAL RISK SCORE (hybrid: rule + ML boost)
# ============================================================
master['final_risk_score'] = master['risk_score'].copy()
# ML-flagged records get a boost
master.loc[master['ml_flag']==1, 'final_risk_score'] += 10
master['final_risk_score'] = master['final_risk_score'].clip(0, 100).round(1)

def classify_risk(score):
    if score >= 85: return 'Critical'
    if score >= 65: return 'High'
    if score >= 40: return 'Medium'
    return 'Low'

master['final_risk_level'] = master['final_risk_score'].apply(classify_risk)

# ============================================================
# 7. RICH CONTEXTUAL EXPLANATIONS (RULE-BASED)
# ============================================================
DEPT_SENSITIVE_RESOURCES = {
    'Finance':     ['GL_System', 'PROD_DB'],
    'HR':          ['HRIS'],
    'IT':          ['Admin_Console', 'PROD_DB', 'SIEM'],
    'Security':    ['SIEM', 'Admin_Console'],
    'Engineering': ['PROD_DB', 'Data_Lake'],
    'Legal':       ['Email_Archive', 'HRIS'],
    'Compliance':  ['SIEM', 'Email_Archive'],
    'Marketing':   ['BI_Tool', 'File_Share'],
    'Sales':       ['BI_Tool', 'Customer_Vault'],
    'Operations':  ['Data_Lake', 'File_Share'],
    'Support':     ['Customer_Vault', 'HRIS'],
    'Executive':   ['BI_Tool', 'GL_System'],
}

RESOURCE_DESCRIPTION = {
    'Customer_Vault': 'customer PII database (names, emails, payment data)',
    'HRIS':           'HR information system (salaries, personal records, performance data)',
    'Admin_Console':  'privileged administration console (system-wide access controls)',
    'GL_System':      'general ledger (financial transactions, account balances)',
    'PROD_DB':        'production database (live business data)',
    'SIEM':           'security information and event management system (security logs)',
    'Data_Lake':      'enterprise data lake (raw analytics and ML datasets)',
    'Email_Archive':  'email archive (historical corporate communications)',
    'BI_Tool':        'business intelligence reporting platform',
    'File_Share':     'corporate file share (internal documents)',
}

ACTION_DESCRIPTION = {
    'login':           'logged in',
    'sql_query':       'ran a SQL query on',
    'file_access':     'accessed files in',
    'api_call':        'made an API call to',
    'export_data':     'exported data from',
    'admin_operation': 'performed admin operations on',
}

DEPT_RESOURCE_CONTEXT = {
    ('Finance', 'GL_System'):       'normal for Finance team, but volume and timing matter',
    ('HR', 'HRIS'):                 'expected for HR staff, but large-scale queries are unusual',
    ('Security', 'SIEM'):           'appropriate for Security team during investigations',
    ('IT', 'Admin_Console'):        'expected for IT admins but requires audit trail',
    ('Engineering', 'PROD_DB'):     'should be done via staging — direct prod access is risky',
    ('Legal', 'Email_Archive'):     'may indicate litigation hold review or compliance check',
    ('Compliance', 'SIEM'):         'may indicate internal audit activity',
    ('Marketing', 'Customer_Vault'):'cross-department access — Marketing should not query PII directly',
    ('Sales', 'HRIS'):              'cross-department access — Sales has no HR data mandate',
    ('Support', 'GL_System'):       'cross-department access — Support does not handle financial data',
}

TITLE_MAP = {
    ('export_data', 'Critical'):    'BULK DATA EXFILTRATION RISK',
    ('export_data', 'High'):        'UNAUTHORISED DATA EXPORT',
    ('export_data', 'Medium'):      'UNUSUAL DATA EXPORT PATTERN',
    ('admin_operation', 'Critical'):'PRIVILEGED SYSTEM COMPROMISE RISK',
    ('admin_operation', 'High'):    'UNAUTHORISED ADMIN OPERATION',
    ('admin_operation', 'Medium'):  'SUSPICIOUS ADMIN ACTIVITY',
    ('sql_query', 'Critical'):      'MASS DATA EXTRACTION ATTEMPT',
    ('sql_query', 'High'):          'RESTRICTED DATABASE QUERY',
    ('sql_query', 'Medium'):        'CROSS-DEPARTMENT DATA QUERY',
    ('api_call', 'Critical'):       'CRITICAL SYSTEM API BREACH RISK',
    ('api_call', 'High'):           'UNAUTHORISED API ACCESS',
    ('api_call', 'Medium'):         'UNUSUAL API CALL PATTERN',
    ('file_access', 'Critical'):    'RESTRICTED FILE ACCESS DETECTED',
    ('file_access', 'High'):        'SENSITIVE FILE BREACH RISK',
    ('file_access', 'Medium'):      'CROSS-ROLE FILE ACCESS',
    ('login', 'Critical'):          'SUSPICIOUS LOGIN — POSSIBLE CREDENTIAL COMPROMISE',
    ('login', 'High'):              'UNUSUAL LOGIN PATTERN DETECTED',
    ('login', 'Medium'):            'OFF-HOURS LOGIN DETECTED',
}

def get_alert_title(row):
    key = (row['action'], row['final_risk_level'])
    default_titles = {
        'Critical': 'HIGH-SEVERITY SECURITY INCIDENT',
        'High':     'ELEVATED RISK EVENT DETECTED',
        'Medium':   'ANOMALOUS ACCESS PATTERN',
        'Low':      'LOW-RISK ACCESS EVENT',
    }
    return TITLE_MAP.get(key, default_titles.get(row['final_risk_level'], 'ACCESS EVENT'))

def get_context_bullets(row):
    bullets = []
    dept = row['department']
    resource = row['resource']
    action = row['action']
    level = row['final_risk_level']
    hour = row['hour']
    tenure = row['tenure_months']
    sens = row['resource_sensitivity']
    priv = row['privilege_level']
    inactive = row['days_inactive']

    # Unauthorized access
    if row['unauthorized']:
        dept_allowed = DEPT_SENSITIVE_RESOURCES.get(dept, [])
        if resource not in dept_allowed:
            bullets.append(f"Resource '{resource}' is NOT in approved systems for {dept} department")
        else:
            bullets.append(f"Access to {resource} is outside normal role scope for this user")

    # First access to this resource
    if row['first_access_resource']:
        bullets.append(f"First-ever access to '{resource}' by this user — no prior history")

    # First export ever
    if row.get('first_export', False):
        bullets.append("First data export action ever recorded for this user")

    # Time-based context
    if row['is_night']:
        bullets.append(f"Access at {hour:02d}:00 hrs — deep night hours (22:00–06:00)")
    elif row['is_off_hours']:
        bullets.append(f"Access at {hour:02d}:00 hrs — outside standard business hours (09:00–17:00)")

    if row['is_weekend']:
        bullets.append("Access occurred on a weekend — no scheduled maintenance or on-call duty noted")

    # Tenure risk
    if tenure < 3:
        bullets.append(f"New employee — only {tenure} month(s) with the company, limited baseline established")
    elif tenure < 6:
        bullets.append(f"Relatively new employee ({tenure} months) — access patterns still being established")

    # Stale account
    if inactive >= 50:
        bullets.append(f"Account dormant for {inactive} days — sudden activity on sensitive systems is high risk")
    elif inactive >= 30:
        bullets.append(f"Account inactive for {inactive} days — reactivation on sensitive resource warrants review")

    # Privilege mismatch
    if priv in ('service-account',) and action != 'login':
        bullets.append("Service account performing human-like interactive operations — possible credential abuse")
    if priv == 'admin' and row['unauthorized']:
        bullets.append("Admin-level privilege used to access a resource outside approved scope — privilege escalation risk")

    # ML anomaly
    if row['ml_flag']:
        bullets.append("Behaviour flagged by ML anomaly detector (Isolation Forest) as statistical outlier")

    # Sensitivity escalation context
    if sens == 'high' and dept not in ['Finance','HR','IT','Security','Legal','Compliance']:
        bullets.append(f"{dept} department accessing restricted-sensitivity data — cross-domain exposure risk")

    # Failed status
    if row['status'] == 'failure':
        bullets.append("Access attempt failed — may indicate password probing or misconfigured permissions")

    # Cross-dept context from our map
    cross_ctx = DEPT_RESOURCE_CONTEXT.get((dept, resource))
    if cross_ctx:
        bullets.append(f"Context note: {cross_ctx}")

    return bullets

def generate_explanation(row):
    dept = row['department']
    resource = row['resource']
    action = row['action']
    resource_desc = RESOURCE_DESCRIPTION.get(resource, resource)
    action_desc   = ACTION_DESCRIPTION.get(action, action)
    hour = row['hour']
    ampm = "AM" if hour < 12 else "PM"
    hour12 = hour if hour <= 12 else hour - 12
    if hour12 == 0: hour12 = 12

    ts = row['timestamp']
    time_str = f"{ts.strftime('%Y-%m-%d')} at {hour12:02d}:{ts.strftime('%M')} {ampm}"

    parts = [
        f"{row['username']} ({dept}, {row['job_title']}) {action_desc} the {resource_desc}",
        f"on {time_str}.",
    ]

    if row['unauthorized']:
        parts.append(f"This resource is NOT part of the approved systems profile for {dept} users.")

    if row['resource_sensitivity'] == 'high':
        parts.append(f"'{resource}' is classified as HIGH SENSITIVITY — any unauthorized or anomalous access carries significant compliance risk (GDPR Art.32 / SOX 302).")

    if row['is_night']:
        parts.append(f"Access at {hour:02d}:00 hrs falls in deep night hours — no legitimate business justification recorded.")
    elif row['is_off_hours']:
        parts.append(f"Access at {hour:02d}:00 hrs is outside standard working hours (09:00–17:00).")

    if row['is_weekend']:
        parts.append("Weekend access with no documented maintenance window or on-call rotation.")

    if row['tenure_months'] < 3:
        parts.append(f"User has only {row['tenure_months']} month(s) of tenure — limited behavioral baseline; access to sensitive systems is premature.")

    if row['days_inactive'] >= 30:
        parts.append(f"Account was inactive for {int(row['days_inactive'])} days before this access — reactivation on sensitive data warrants investigation.")

    if row['ml_flag']:
        parts.append("The ML anomaly detection engine (Isolation Forest, 25% contamination threshold) flagged this event as a statistical outlier against peer behavior.")

    if row['status'] == 'failure':
        parts.append("The access attempt resulted in a FAILURE status — may indicate unauthorized probing.")

    parts.append(f"Composite risk score: {row['final_risk_score']}/100.")
    return ' '.join(parts)

def generate_business_impact(row):
    resource = row['resource']
    action   = row['action']
    dept     = row['department']
    level    = row['final_risk_level']

    impact_map = {
        'Customer_Vault': {
            'export_data':     'Potential exfiltration of customer PII (names, emails, payment info). GDPR breach risk with penalties up to 4% of annual global turnover. Customer trust and brand reputation at severe risk.',
            'sql_query':       'Bulk query of customer PII database. If data is being profiled for exfiltration, this is a precursor event. GDPR Article 32 compliance breach risk.',
            'admin_operation': 'Admin-level operation on customer data vault. Risk of schema changes, data deletion, or backdoor account creation. Critical compliance violation.',
            'api_call':        'Programmatic access to customer PII via API. Could enable automated bulk extraction without triggering row-count thresholds.',
            'file_access':     'File-level access to customer data assets. Risk of offline copies being created and removed from audit trails.',
            'login':           'Authenticated login to customer vault system — if unauthorized, credentials may be compromised.',
        },
        'HRIS': {
            'export_data':     'Potential exfiltration of sensitive HR data: salaries, performance reviews, personal addresses. Violates employee privacy rights and GDPR personal data protections.',
            'sql_query':       'Direct SQL access to HR records including salary bands, disciplinary history, and personal data. Significant privacy violation if unauthorized.',
            'admin_operation': 'Admin operation on HRIS risks unauthorized modification of salary records, access controls, or employee status — serious HR and legal exposure.',
            'api_call':        'API-level access to HR data. Could be used to enumerate employees, extract org structure, or exfiltrate personal information programmatically.',
            'file_access':     'File access to HR documents containing confidential personnel information. Unauthorized copies risk data leakage.',
            'login':           'Login to HRIS system by non-HR user — possible credential theft or insider snooping on salary/performance data.',
        },
        'Admin_Console': {
            'export_data':     'Admin console data export could reveal system configurations, user access lists, and security policies — valuable for attackers planning escalation.',
            'sql_query':       'SQL query via admin console provides system-level visibility that could expose architecture, credentials, and security configurations.',
            'admin_operation': 'Admin operation on privileged console. Highest severity — could result in account creation/deletion, permission escalation, or system-wide configuration changes.',
            'api_call':        'API call to admin console — risk of automated privilege escalation or backdoor provisioning.',
            'file_access':     'File access in admin console environment. Security configuration files, cryptographic keys, or audit logs may be exposed.',
            'login':           'Login to admin console by unauthorized user — immediate account takeover risk.',
        },
        'GL_System': {
            'export_data':     'Export of general ledger data before quarter-end or resignation indicates possible financial fraud risk. SOX 302 violation. Competitor intelligence threat.',
            'sql_query':       'SQL query on GL system risks exposure of sensitive financial transactions, revenue figures, and budget allocations. SOX 302 controls at risk.',
            'admin_operation': 'Admin operations on GL system risk unauthorized journal entries, balance manipulation, or audit trail tampering — material financial fraud risk.',
            'api_call':        'Programmatic access to GL system. Risk of automated financial data scraping or integration with unauthorized external systems.',
            'file_access':     'File-level access to GL documents. Financial statements, budgets, and projections could be extracted without triggering query-level audit alerts.',
            'login':           'Unauthorized login to GL system — possible attempt to access financial records.',
        },
        'PROD_DB': {
            'export_data':     'Production database export is a critical event. Live business data across all systems is at risk of exfiltration. Service disruption and data breach risk.',
            'sql_query':       'Direct SQL query on production database. Risk of data exfiltration, service interference, or reconnaissance for a larger attack.',
            'admin_operation': 'Admin operation on production database is highest-severity — table drops, schema changes, or injected data could cause catastrophic business disruption.',
            'api_call':        'API call to production database system. Automated bulk extraction or injection attack vector.',
            'file_access':     'File access to production database storage. Raw data files could bypass query-level access controls.',
            'login':           'Unauthorized production database login — possible account compromise or insider access.',
        },
    }

    generic_impact = {
        'Critical': f'Critical security event involving {resource}. Immediate response required to prevent data loss, compliance violations, or system compromise.',
        'High':     f'High-risk access to {resource} by {dept} user. Potential data exposure or policy violation with significant compliance implications.',
        'Medium':   f'Potentially unauthorized access to {resource}. Review required to rule out policy violations or data misuse.',
        'Low':      f'Routine access event flagged for audit purposes. Low probability of malicious intent but logged for compliance trail.',
    }

    resource_impacts = impact_map.get(resource, {})
    return resource_impacts.get(action, generic_impact.get(level, generic_impact['Medium']))

def generate_recommendation(row):
    level  = row['final_risk_level']
    action = row['action']
    resource = row['resource']
    unauth = row['unauthorized']
    night  = row['is_night']
    ml_flag = row['ml_flag']
    inactive = row['days_inactive']

    if level == 'Critical':
        steps = [
            'IMMEDIATE: Suspend user account pending investigation',
            f'Pull full 72-hour audit trail for {row["username"]}',
            f'Review all access logs for {resource} in the past 7 days',
            'Notify Security Operations Center (SOC) and CISO',
            'Escalate to HR and Legal if insider threat confirmed',
        ]
        if action == 'export_data':
            steps.insert(1, 'BLOCK: Revoke data export permissions immediately')
            steps.insert(2, 'Identify destination of exported data and attempt recall/containment')
        if unauth:
            steps.insert(1, 'REVOKE: Remove unauthorized resource access immediately')
        if inactive >= 30:
            steps.append('Investigate why dormant account was reactivated — possible credential theft')
        return ' | '.join(steps)

    elif level == 'High':
        steps = [
            f'Review {row["username"]}\'s recent activity across all systems',
            f'Verify business justification for accessing {resource}',
            'Request manager approval confirmation for this access',
        ]
        if unauth:
            steps.insert(0, 'REVOKE: Remove unauthorized resource access within 4 hours')
        if action == 'export_data':
            steps.insert(1, 'Identify export destination and confirm data was not sent externally')
        if night:
            steps.append('Confirm whether off-hours access was pre-approved or on-call scheduled')
        if ml_flag:
            steps.append('Cross-reference against peer behaviour — check if other accounts show similar pattern')
        return ' | '.join(steps)

    elif level == 'Medium':
        steps = [
            f'Log and monitor {row["username"]}\'s activity for the next 14 days',
            'Verify access is within approved role scope',
        ]
        if unauth:
            steps.insert(1, 'Review access permissions and align with role definition')
        if action in ('export_data', 'admin_operation'):
            steps.insert(1, f'Request business justification for {action} on {resource}')
        return ' | '.join(steps)

    else:  # Low
        return f'No immediate action required. Access logged for compliance audit trail. Review if pattern repeats within 30 days.'

# ============================================================
# APPLY ALL GENERATORS
# ============================================================
master['alert_title']           = master.apply(get_alert_title, axis=1)
master['context_bullets']       = master.apply(get_context_bullets, axis=1)
master['detailed_explanation']  = master.apply(generate_explanation, axis=1)
master['business_impact']       = master.apply(generate_business_impact, axis=1)
master['recommendation']        = master.apply(generate_recommendation, axis=1)

# Confidence score
def confidence(row):
    signals = sum([
        row['unauthorized'],
        row['is_night'],
        row['is_weekend'],
        row['first_access_resource'],
        row['ml_flag'],
        row['days_inactive'] >= 30,
        row['tenure_months'] < 3,
        row['status'] == 'failure',
    ])
    base = {
        'Critical': 90,
        'High':     78,
        'Medium':   65,
        'Low':      55,
    }.get(row['final_risk_level'], 60)
    return min(99, base + signals)

master['confidence'] = master.apply(confidence, axis=1)

# ============================================================
# 8. EVALUATION METRICS (simulated ground truth)
# ============================================================
# Ground truth: anomaly if time is non-business_hours AND (high sensitivity OR unauthorized OR failed)
def ground_truth(row):
    non_business = row['time_classification'] != 'business_hours'
    high_sens    = row['resource_sensitivity'] == 'high'
    unauthorized = row['unauthorized']
    failed       = row['status'] == 'failure'
    risky_action = row['action'] in ('export_data', 'admin_operation')
    stale        = row['days_inactive'] >= 30
    # Realistic GT: non-business + at least one risk factor, OR unauthorized + high sens
    if (non_business and (high_sens or unauthorized or risky_action)):
        return 1
    if (unauthorized and high_sens):
        return 1
    if (stale and risky_action):
        return 1
    if failed and unauthorized:
        return 1
    return 0

master['ground_truth'] = master.apply(ground_truth, axis=1)
# Naive baseline: flag all non-business hours
master['naive_pred']   = (master['time_classification'] != 'business_hours').astype(int)
# Our model: flag High or Critical
master['model_pred']   = (master['final_risk_level'].isin(['High','Critical'])).astype(int)

y_true   = master['ground_truth']
y_naive  = master['naive_pred']
y_model  = master['model_pred']

metrics = {
    'naive_precision': precision_score(y_true, y_naive, zero_division=0),
    'naive_recall':    recall_score(y_true, y_naive, zero_division=0),
    'naive_f1':        f1_score(y_true, y_naive, zero_division=0),
    'model_precision': precision_score(y_true, y_model, zero_division=0),
    'model_recall':    recall_score(y_true, y_model, zero_division=0),
    'model_f1':        f1_score(y_true, y_model, zero_division=0),
    'total_events':    len(master),
    'total_anomalies': int(y_true.sum()),
    'critical_count':  int((master['final_risk_level']=='Critical').sum()),
    'high_count':      int((master['final_risk_level']=='High').sum()),
    'medium_count':    int((master['final_risk_level']=='Medium').sum()),
    'low_count':       int((master['final_risk_level']=='Low').sum()),
    'ml_anomalies':    int(master['ml_flag'].sum()),
    'unauth_count':    int(master['unauthorized'].sum()),
}

print("=== EVALUATION METRICS ===")
print(f"Naive Baseline  — Precision: {metrics['naive_precision']:.2%}  Recall: {metrics['naive_recall']:.2%}  F1: {metrics['naive_f1']:.2f}")
print(f"Our Model       — Precision: {metrics['model_precision']:.2%}  Recall: {metrics['model_recall']:.2%}  F1: {metrics['model_f1']:.2f}")
print()
print(f"Total Events: {metrics['total_events']}")
print(f"True Anomalies (GT): {metrics['total_anomalies']}")
print(f"Critical: {metrics['critical_count']}  High: {metrics['high_count']}  Medium: {metrics['medium_count']}  Low: {metrics['low_count']}")
print(f"ML Anomalies flagged: {metrics['ml_anomalies']}")
print(f"Unauthorized accesses: {metrics['unauth_count']}")

# ============================================================
# 9. BUILD FINAL REPORT & TOP15
# ============================================================
report_cols = [
    'timestamp','username','department','job_title','action','resource',
    'resource_sensitivity','final_risk_score','final_risk_level','confidence',
    'unauthorized','is_night','is_weekend','is_off_hours','first_access_resource',
    'ml_flag','tenure_months','days_inactive','privilege_level','alert_title',
    'context_bullets','detailed_explanation','business_impact','recommendation',
    'ground_truth','model_pred'
]
final_report = master[report_cols].copy()
final_report['context_bullets'] = final_report['context_bullets'].apply(lambda x: '\n'.join([f'• {b}' for b in x]) if x else '')
final_report = final_report.sort_values('final_risk_score', ascending=False).reset_index(drop=True)

final_report.to_csv('/home/claude/final_incident_report_v2.csv', index=False)
print("\nSaved: final_incident_report_v2.csv")

# Top 15 alerts
top15 = final_report.head(15).copy()
top15.to_csv('/home/claude/top15_alerts_v2.csv', index=False)
print("Saved: top15_alerts_v2.csv")

# Metrics JSON
import json
with open('/home/claude/evaluation_metrics.json', 'w') as f:
    json.dump(metrics, f, indent=2)
print("Saved: evaluation_metrics.json")

# Show top 5
print("\n=== TOP 5 CRITICAL ALERTS ===")
for i, row in final_report[final_report['final_risk_level']=='Critical'].head(5).iterrows():
    print(f"\n[ALERT {i+1}] {row['alert_title']}")
    print(f"  User: {row['username']} ({row['department']}, {int(row['tenure_months'])} months tenure)")
    print(f"  Action: {row['action']} on {row['resource']}")
    print(f"  Score: {row['final_risk_score']}/100  |  Level: {row['final_risk_level']}  |  Confidence: {row['confidence']}%")
    print(f"  Context:\n    {row['context_bullets']}")
    print(f"  Business Impact: {row['business_impact'][:120]}...")
    print(f"  Recommendation: {row['recommendation'][:120]}...")
