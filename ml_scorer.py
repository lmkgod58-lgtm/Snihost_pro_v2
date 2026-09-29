#!/usr/bin/env python3
"""
Predictive ML Scoring Module
SOUTH AFRICA EDITION
Learns from SA burn-test results to predict which SNI hosts will work
Trains per-ISP models for MTN, Vodacom, Telkom, Cell C
"""

import json
import os
import time
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

DATA_DIR = os.path.expanduser("~/snihost_pro/ml_data")
MODEL_FILE = os.path.join(DATA_DIR, "sa_sni_model.json")
FEATURE_LOG = os.path.join(DATA_DIR, "sa_feature_log.json")
BURN_LOG = os.path.expanduser("~/snihost_pro/burn_test_log.json")

os.makedirs(DATA_DIR, exist_ok=True)

# SA-specific feature weights per ISP
SA_FEATURE_WEIGHTS = {
    'mtn': {
        'category_score': 8.0,      # MTN cares about category
        'tls_version_score': 4.0,
        'http_status_score': 3.0,
        'speed_score': 2.0,
        'has_cdn': -5.0,            # MTN penalizes CDN heavily
        'cdn_score': -3.0,
        'single_ip': 3.0,
        'has_reverse_dns': 1.0,
        'in_personal_db': 12.0,
        'tls_success': 6.0,
        'heuristic_score': 0.4,
        'content_legitimacy': 8.0,   # MTN checks content
        'static_ip': 5.0,           # MTN prefers static
        'tunnel_risk': -8.0,        # MTN bans tunnels
    },
    'vodacom': {
        'category_score': 7.0,
        'tls_version_score': 5.0,
        'http_status_score': 4.0,
        'speed_score': 2.0,
        'has_cdn': -4.0,
        'cdn_score': -2.0,
        'single_ip': 4.0,
        'has_reverse_dns': 2.0,
        'in_personal_db': 10.0,
        'tls_success': 7.0,
        'heuristic_score': 0.5,
        'content_legitimacy': 7.0,
        'static_ip': 4.0,
        'strict_sni_match': 6.0,     # Vodacom checks SNI strictly
    },
    'telkom': {
        'category_score': 6.0,
        'tls_version_score': 3.0,
        'http_status_score': 3.0,
        'speed_score': 1.5,
        'has_cdn': -1.0,            # Telkom less strict on CDN
        'cdn_score': 0.5,
        'single_ip': 2.0,
        'has_reverse_dns': 1.0,
        'in_personal_db': 10.0,
        'tls_success': 5.0,
        'heuristic_score': 0.4,
        'content_legitimacy': 6.0,
        'static_ip': 2.0,
        'edu_portal_match': 8.0,     # Telkom checks edu portal
    },
    'cell_c': {
        'category_score': 6.0,
        'tls_version_score': 3.0,
        'http_status_score': 3.0,
        'speed_score': 1.5,
        'has_cdn': -3.0,
        'cdn_score': -1.5,
        'single_ip': 3.0,
        'has_reverse_dns': 1.0,
        'in_personal_db': 10.0,
        'tls_success': 5.0,
        'heuristic_score': 0.4,
        'content_legitimacy': 5.0,
        'static_ip': 3.0,
    }
}

# Default weights if ISP not specified
DEFAULT_WEIGHTS = {
    'category_score': 6.0,
    'tls_version_score': 3.5,
    'http_status_score': 3.0,
    'speed_score': 1.5,
    'has_cdn': -3.0,
    'cdn_score': -1.5,
    'single_ip': 2.5,
    'has_reverse_dns': 1.0,
    'in_personal_db': 10.0,
    'tls_success': 5.0,
    'heuristic_score': 0.4,
    'content_legitimacy': 6.0,
    'static_ip': 3.0,
}

# ============ FEATURE EXTRACTION ============

def extract_features(scan_result, content_result=None, isp=''):
    """
    Extract SA-specific features from scan results
    """
    features = {}
    
    # 1. Category
    category = scan_result.get('category', 'other')
    cat_scores = {
        'government': 5, 'education': 4, 'health': 3,
        'job': 3, 'social': 2, 'cdn': 1, 'other': 0
    }
    features['category_score'] = cat_scores.get(category, 0)
    
    # 2. TLS version
    tls_version = scan_result.get('tls_version', '')
    tls_scores = {'TLSv1.3': 3, 'TLSv1.2': 2, 'TLSv1.1': 1, 'TLSv1.0': 0, None: -1}
    features['tls_version_score'] = tls_scores.get(tls_version, -1)
    
    # 3. HTTP status
    status = scan_result.get('http_status', 0)
    if status == 200:
        features['http_status_score'] = 3
    elif status in (301, 302):
        features['http_status_score'] = 2
    elif status in (403, 401):
        features['http_status_score'] = 1
    else:
        features['http_status_score'] = 0
    
    # 4. Speed
    tls_time = scan_result.get('tls_time_ms', 9999)
    if tls_time < 50:
        features['speed_score'] = 3
    elif tls_time < 100:
        features['speed_score'] = 2
    elif tls_time < 500:
        features['speed_score'] = 1
    else:
        features['speed_score'] = 0
    
    # 5. CDN detection
    cdn = scan_result.get('cdn', None)
    features['has_cdn'] = 1 if cdn else 0
    cdn_scores = {'cloudflare': 3, 'aws': 2, 'fastly': 2, 'akamai': 2, None: 0}
    features['cdn_score'] = cdn_scores.get(cdn, 0)
    
    # 6. DNS stability
    ipv4_count = len(scan_result.get('ipv4', []))
    features['single_ip'] = 1 if ipv4_count == 1 else 0
    
    # 7. Reverse DNS
    features['has_reverse_dns'] = 1 if scan_result.get('reverse_dns') else 0
    
    # 8. Personal DB
    features['in_personal_db'] = 1 if scan_result.get('in_personal_db') else 0
    
    # 9. TLS success
    features['tls_success'] = 1 if scan_result.get('tls_success') else 0
    
    # 10. Heuristic score
    features['heuristic_score'] = scan_result.get('score', 0)
    
    # 11. SA-specific: Content legitimacy
    if content_result:
        legitimacy = content_result.get('legitimacy_score', 0)
        features['content_legitimacy'] = min(legitimacy / 10, 5)  # Scale 0-5
    else:
        features['content_legitimacy'] = 0
    
    # 12. SA-specific: Static IP
    features['static_ip'] = 1 if scan_result.get('is_static') else 0
    
    # 13. SA-specific: Tunnel risk (for MTN)
    if isp.lower() == 'mtn':
        tunnel_risk = scan_result.get('tunnel_risk', 0)
        features['tunnel_risk'] = -1 if tunnel_risk > 0 else 1
    
    # 14. SA-specific: Strict SNI match (for Vodacom)
    if isp.lower() == 'vodacom':
        strict_sni = scan_result.get('strict_sni_match', False)
        features['strict_sni_match'] = 1 if strict_sni else 0
    
    # 15. SA-specific: Edu portal (for Telkom)
    if isp.lower() == 'telkom':
        edu_portal = scan_result.get('edu_portal_match', False)
        features['edu_portal_match'] = 1 if edu_portal else 0
    
    return features

# ============ PER-ISP ML MODEL ============

class SAISPClassifier:
    """
    Per-ISP classifier using weighted rules
    Trains separately for each SA ISP
    """
    
    def __init__(self, isp=''):
        self.isp = isp.lower().strip() if isp else 'default'
        self.weights = self._get_initial_weights()
        self.bias = -10.0
        self.trained = False
        self.training_data = []
        self.isp_specific_accuracy = {}
    
    def _get_initial_weights(self):
        """Get ISP-specific initial weights"""
        if self.isp in SA_FEATURE_WEIGHTS:
            return SA_FEATURE_WEIGHTS[self.isp].copy()
        return DEFAULT_WEIGHTS.copy()
    
    def predict_score(self, features):
        """
        Predict success probability (0-100)
        """
        score = self.bias
        
        for feature_name, weight in self.weights.items():
            feature_value = features.get(feature_name, 0)
            score += feature_value * weight
        
        probability = max(0, min(100, score * 2))
        return probability
    
    def train(self, training_data, epochs=100):
        """
        Train on burn-test results per ISP
        """
        if not training_data:
            print(f"{Fore.YELLOW}No training data for {self.isp}{Style.RESET_ALL}")
            return False
        
        self.training_data = training_data
        
        # Separate by ISP if mixed
        isp_data = [s for s in training_data 
                   if s.get('isp', '').lower() == self.isp or not self.isp]
        
        if len(isp_data) < 5:
            print(f"{Fore.YELLOW}Need 5+ samples for {self.isp}. Have {len(isp_data)}.{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.CYAN}Training {self.isp.upper()} model on {len(isp_data)} samples...{Style.RESET_ALL}")
        
        learning_rate = 0.1
        
        for epoch in range(epochs):
            for sample in isp_data:
                features = sample['features']
                actual = 1 if sample['worked'] else 0
                
                predicted = self.predict_score(features) / 100.0
                error = actual - predicted
                
                for feature_name in self.weights:
                    if feature_name in features:
                        feature_value = features[feature_name]
                        self.weights[feature_name] += learning_rate * error * feature_value
                
                self.bias += learning_rate * error
        
        self.trained = True
        
        # Calculate accuracy
        correct = 0
        for sample in isp_data:
            pred = self.predict_score(sample['features'])
            predicted_worked = pred >= 50
            actual_worked = sample['worked']
            if predicted_worked == actual_worked:
                correct += 1
        
        accuracy = (correct / len(isp_data)) * 100
        self.isp_specific_accuracy[self.isp] = accuracy
        
        print(f"\n{Fore.GREEN}=== {self.isp.upper()} Model Trained ==={Style.RESET_ALL}")
        print(f"Samples: {len(isp_data)}")
        print(f"Accuracy: {accuracy:.1f}%")
        
        # Show top weights
        print(f"\nLearned weights:")
        for name, weight in sorted(self.weights.items(), key=lambda x: -abs(x[1])):
            print(f"  {name}: {weight:.3f}")
        
        return True
    
    def save(self, filepath):
        data = {
            'isp': self.isp,
            'weights': self.weights,
            'bias': self.bias,
            'trained': self.trained,
            'accuracy': self.isp_specific_accuracy.get(self.isp, 0),
            'training_count': len(self.training_data)
        }
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
    
    def load(self, filepath):
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                data = json.load(f)
            self.weights = data.get('weights', self.weights)
            self.bias = data.get('bias', self.bias)
            self.trained = data.get('trained', False)
            return True
        return False

# ============ MULTI-ISP MODEL MANAGER ============

class SAModelManager:
    """
    Manages separate models for each SA ISP
    """
    
    def __init__(self):
        self.models = {}
        self.load_all()
    
    def get_model(self, isp):
        isp = isp.lower().strip() if isp else 'default'
        
        if isp not in self.models:
            model = SAISPClassifier(isp)
            model_path = os.path.join(DATA_DIR, f"model_{isp}.json")
            model.load(model_path)
            self.models[isp] = model
        
        return self.models[isp]
    
    def load_all(self):
        """Load all existing ISP models"""
        for isp in ['mtn', 'vodacom', 'telkom', 'cell_c', 'default']:
            model_path = os.path.join(DATA_DIR, f"model_{isp}.json")
            if os.path.exists(model_path):
                model = SAISPClassifier(isp)
                if model.load(model_path):
                    self.models[isp] = model
    
    def train_isp(self, isp, training_data):
        """Train a specific ISP model"""
        model = self.get_model(isp)
        success = model.train(training_data)
        
        if success:
            model_path = os.path.join(DATA_DIR, f"model_{isp}.json")
            model.save(model_path)
        
        return success
    
    def predict(self, features, isp):
        """Get prediction for specific ISP"""
        model = self.get_model(isp)
        return model.predict_score(features)

# ============ TRAINING DATA MANAGEMENT ============

def load_burn_test_history():
    if not os.path.exists(BURN_LOG):
        return []
    try:
        with open(BURN_LOG, 'r') as f:
            return json.load(f)
    except:
        return []

def load_feature_log():
    if not os.path.exists(FEATURE_LOG):
        return {}
    try:
        with open(FEATURE_LOG, 'r') as f:
            return json.load(f)
    except:
        return {}

def save_feature_log(feature_log):
    with open(FEATURE_LOG, 'w') as f:
        json.dump(feature_log, f, indent=2)

def log_scan_features(domain, features):
    feature_log = load_feature_log()
    feature_log[domain] = features
    save_feature_log(feature_log)

def build_training_data():
    burn_history = load_burn_test_history()
    feature_log = load_feature_log()
    
    training_data = []
    
    for entry in burn_history:
        domain = entry.get('domain', '')
        worked = entry.get('worked', False)
        isp = entry.get('isp', '')
        
        domain_features = feature_log.get(domain)
        
        if domain_features:
            training_data.append({
                'domain': domain,
                'features': domain_features,
                'worked': worked,
                'isp': isp
            })
    
    return training_data

# ============ PREDICTION INTERFACE ============

class SAPredictor:
    """
    SA-specific prediction interface
    """
    
    def __init__(self):
        self.manager = SAModelManager()
    
    def predict(self, scan_result, content_result=None, isp=''):
        """
        Predict success probability for SA ISP
        """
        features = extract_features(scan_result, content_result, isp)
        
        domain = scan_result.get('domain', '')
        if domain:
            log_scan_features(domain, features)
        
        # Get ISP-specific prediction
        probability = self.manager.predict(features, isp)
        
        # Determine confidence
        if probability >= 70:
            confidence = 'HIGH'
            color = Fore.GREEN
        elif probability >= 45:
            confidence = 'MEDIUM'
            color = Fore.YELLOW
        else:
            confidence = 'LOW'
            color = Fore.RED
        
        # Get model info
        model = self.manager.get_model(isp)
        
        return {
            'domain': domain,
            'isp': isp,
            'predicted_probability': round(probability, 1),
            'confidence_level': confidence,
            'model_trained': model.trained,
            'model_accuracy': model.isp_specific_accuracy.get(isp.lower(), 0),
            'features': features
        }
    
    def train_from_history(self, isp=''):
        """
        Train specific ISP model from burn-test history
        """
        training_data = build_training_data()
        
        if not training_data:
            print(f"{Fore.RED}No burn-test data found{Style.RESET_ALL}")
            return False
        
        # Filter by ISP if specified
        if isp:
            isp_data = [t for t in training_data if t.get('isp', '').lower() == isp.lower()]
            if len(isp_data) < 5:
                print(f"{Fore.YELLOW}Only {len(isp_data)} samples for {isp}. Need 5+.{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}Training with all data instead.{Style.RESET_ALL}")
                isp_data = training_data
        else:
            isp_data = training_data
        
        if len(isp_data) < 5:
            print(f"{Fore.YELLOW}Need 5+ total samples. Have {len(isp_data)}.{Style.RESET_ALL}")
            return False
        
        # Train for specified ISP or all
        if isp:
            return self.manager.train_isp(isp, isp_data)
        else:
            success = False
            for target_isp in ['mtn', 'vodacom', 'telkom', 'cell_c']:
                isp_specific = [t for t in isp_data if t.get('isp', '').lower() == target_isp]
                if len(isp_specific) >= 5:
                    if self.manager.train_isp(target_isp, isp_specific):
                        success = True
            return success

# ============ DISPLAY ============

def display_prediction(prediction):
    p = prediction
    color = Fore.GREEN if p['predicted_probability'] >= 70 else Fore.YELLOW if p['predicted_probability'] >= 45 else Fore.RED
    
    print(f"\n{color}{'='*50}{Style.RESET_ALL}")
    print(f"{color}  SA ML Prediction: {p['domain']}{Style.RESET_ALL}")
    print(f"{color}  ISP: {p['isp'] or 'Generic'}{Style.RESET_ALL}")
    print(f"{color}{'='*50}{Style.RESET_ALL}")
    print(f"  Probability: {color}{p['predicted_probability']}%{Style.RESET_ALL}")
    print(f"  Confidence: {p['confidence_level']}")
    print(f"  Model Trained: {'✅' if p['model_trained'] else '❌'}")
    if p['model_trained']:
        print(f"  Model Accuracy: {p['model_accuracy']:.1f}%")
    
    print(f"\n  Recommendation:")
    if p['predicted_probability'] >= 70:
        print(f"  {Fore.GREEN}HIGH PRIORITY — Test this host first!{Style.RESET_ALL}")
    elif p['predicted_probability'] >= 45:
        print(f"  {Fore.YELLOW}MEDIUM PRIORITY — Worth testing{Style.RESET_ALL}")
    else:
        print(f"  {Fore.RED}LOW PRIORITY — Skip unless desperate{Style.RESET_ALL}")

# ============ MAIN ============

def main():
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  SA ML Scorer{Style.RESET_ALL}")
    print(f"{Fore.CYAN}  Per-ISP Machine Learning{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")
    
    predictor = SAPredictor()
    
    print("Select mode:")
    print("1. Train ISP model from burn-test history")
    print("2. Predict single host")
    print("3. Show model status")
    print("4. Reset all models")
    
    choice = input("\nChoice (1-4): ").strip()
    
    if choice == '1':
        print("\nAvailable ISPs: MTN, Vodacom, Telkom, Cell C")
        print("Or press Enter to train all")
        isp = input("ISP: ").strip()
        
        success = predictor.train_from_history(isp)
        if success:
            print(f"\n{Fore.GREEN}Training complete!{Style.RESET_ALL}")
    
    elif choice == '2':
        print(f"\n{Fore.YELLOW}Enter scan features:{Style.RESET_ALL}")
        
        scan_result = {
            'domain': input("Domain: ").strip(),
            'category': input("Category (government/education/health/job/social/cdn/other): ").strip(),
            'tls_version': input("TLS version: ").strip(),
            'http_status': int(input("HTTP status: ").strip() or 0),
            'tls_time_ms': float(input("TLS time (ms): ").strip() or 9999),
            'cdn': input("CDN (cloudflare/aws/fastly/akamai/none): ").strip() or None,
            'ipv4': input("IPv4 (comma-separated): ").strip().split(','),
            'reverse_dns': input("Reverse DNS: ").strip() or None,
            'in_personal_db': input("In personal DB? (y/n): ").strip().lower() == 'y',
            'tls_success': True,
            'score': int(input("Heuristic score: ").strip() or 0),
            'is_static': input("Static IP? (y/n): ").strip().lower() == 'y',
        }
        
        content_result = {
            'legitimacy_score': int(input("Content legitimacy score: ").strip() or 0)
        }
        
        isp = input("ISP: ").strip()
        
        prediction = predictor.predict(scan_result, content_result, isp)
        display_prediction(prediction)
    
    elif choice == '3':
        print(f"\n{Fore.CYAN}=== Model Status ==={Style.RESET_ALL}")
        
        history = load_burn_test_history()
        feature_log = load_feature_log()
        
        print(f"Burn-test entries: {len(history)}")
        print(f"Feature-logged domains: {len(feature_log)}")
        
        for isp in ['mtn', 'vodacom', 'telkom', 'cell_c', 'default']:
            model_path = os.path.join(DATA_DIR, f"model_{isp}.json")
            if os.path.exists(model_path):
                with open(model_path, 'r') as f:
                    data = json.load(f)
                print(f"\n  {isp.upper()}:")
                print(f"    Trained: {'✅' if data.get('trained') else '❌'}")
                print(f"    Accuracy: {data.get('accuracy', 0):.1f}%")
                print(f"    Samples: {data.get('training_count', 0)}")
            else:
                print(f"\n  {isp.upper()}: No model")
    
    elif choice == '4':
        confirm = input(f"{Fore.RED}Delete ALL models? (yes/no): {Style.RESET_ALL}").strip().lower()
        if confirm == 'yes':
            for isp in ['mtn', 'vodacom', 'telkom', 'cell_c', 'default']:
                model_path = os.path.join(DATA_DIR, f"model_{isp}.json")
                if os.path.exists(model_path):
                    os.remove(model_path)
            if os.path.exists(FEATURE_LOG):
                os.remove(FEATURE_LOG)
            print(f"{Fore.GREEN}All models reset.{Style.RESET_ALL}")
    
    else:
        print(f"{Fore.RED}Invalid choice{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
