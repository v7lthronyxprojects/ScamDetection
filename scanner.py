import asyncio
import aiohttp
import requests
import whois
import ssl
import socket
import re
import logging
import os
import json
import base64
import subprocess
import io
from datetime import datetime
from typing import List, Dict, Tuple, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import tldextract
from cryptography.fernet import Fernet
from concurrent.futures import ThreadPoolExecutor
import joblib
import pandas as pd
from dotenv import load_dotenv
import dns.resolver
import urllib3
from urllib3.exceptions import InsecureRequestWarning
from PIL import Image
import pytesseract
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import nmap
from shodan import Shodan
from censys.search import CensysHosts
from wafw00f.main import WAFW00F
from OTXv2 import OTXv2, IndicatorTypes

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score, GridSearchCV

import sublist3r

urllib3.disable_warnings(InsecureRequestWarning)

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scanner.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

KEY_FILE = 'secret.key'

def load_or_create_key() -> Fernet:
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as key_file:
            key = key_file.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as key_file:
            key_file.write(key)
    return Fernet(key)

fernet = load_or_create_key()

Base = declarative_base()

class Cache(Base):
    __tablename__ = 'cache'
    url = Column(String, primary_key=True)
    data = Column(String)
    timestamp = Column(DateTime)
    last_checked = Column(DateTime)

DATABASE_URL = 'sqlite:///cache.db'
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)

def init_cache_db():
    try:
        Base.metadata.create_all(engine)
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Error initializing database: {e}")

init_cache_db()

from contextlib import contextmanager

@contextmanager
def get_db_session():
    session = SessionLocal()
    try:
        yield session
    except Exception as e:
        logger.error(f"Database session error: {e}")
        session.rollback()
        raise
    finally:
        session.close()

def load_cache() -> Dict[str, dict]:
    cache = {}
    with get_db_session() as session:
        cache_entries = session.query(Cache).all()
        for entry in cache_entries:
            try:
                decrypted_data = fernet.decrypt(entry.data.encode()).decode()
                cache[entry.url] = json.loads(decrypted_data)
            except Exception as e:
                logger.error(f"Error decrypting cache entry for {entry.url}: {e}")
    logger.info(f"Loaded {len(cache)} entries from cache.")
    return cache

def save_cache_entry(url: str, data: dict):
    encrypted_data = fernet.encrypt(json.dumps(data).encode()).decode()
    with get_db_session() as session:
        cache_entry = Cache(
            url=url,
            data=encrypted_data,
            timestamp=datetime.now(),
            last_checked=datetime.now()
        )
        session.merge(cache_entry)
        session.commit()
    logger.info(f"Cache entry saved for {url}.")

cache = load_cache()

MODEL_FILE = 'models/scam_detector_model.pkl'

def train_model(data_path: str = 'scam_dataset.csv', model_path: str = MODEL_FILE):
    try:
        if not os.path.exists(data_path):
            logger.warning("Training dataset not found. Skipping training.")
            return

        data = pd.read_csv(data_path)
        X = data['url']
        y = data['label']

        pipeline = Pipeline([
            ('tfidf', TfidfVectorizer()),
            ('clf', RandomForestClassifier(random_state=42))
        ])

        param_grid = {
            'clf__n_estimators': [100, 200],
            'clf__max_depth': [None, 10, 20],
            'clf__min_samples_split': [2, 5],
        }

        grid_search = GridSearchCV(pipeline, param_grid, cv=5, scoring='accuracy', n_jobs=-1)
        grid_search.fit(X, y)

        best_model = grid_search.best_estimator_
        
        scores = cross_val_score(best_model, X, y, cv=5)
        logger.info(f"Cross-validation Accuracy: {scores.mean():.2f} ± {scores.std():.2f}")

        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        joblib.dump(best_model, model_path)
        logger.info("Model trained and saved successfully.")
    except Exception as e:
        logger.error(f"Error training model: {e}")

def load_model() -> Optional[Pipeline]:
    try:
        if not os.path.exists(MODEL_FILE):
            logger.info("Model file not found. Training new model...")
            train_model()
        return joblib.load(MODEL_FILE)
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        return None

model = load_model()

def predict(url: str, model: Pipeline) -> str:
    try:
        return model.predict([url])[0]
    except Exception as e:
        logger.error(f"Error during prediction: {e}")
        return 'Error'

def validate_url(url: str) -> bool:
    try:
        result = urlparse(url)
        is_valid = all([result.scheme in ['http', 'https'], result.netloc])
        logger.debug(f"Validating URL '{url}': {is_valid}")
        return is_valid
    except Exception as e:
        logger.error(f"URL validation error for '{url}': {e}")
        return False

async def analyze_ssl_certificate(url: str) -> Tuple[bool, str, Optional[dict]]:
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        context = ssl.create_default_context()
        context.set_ciphers('HIGH:!aNULL:!eNULL:!MD5:!RC4')
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        loop = asyncio.get_event_loop()
        ssl_check = await loop.run_in_executor(None, _ssl_check_detailed, host, context, url)
        return ssl_check
    except Exception as e:
        logger.error(f"SSL certificate analysis failed: {str(e)}")
        return (False, f"SSL certificate analysis error: {str(e)}", None)

def _ssl_check_detailed(host: str, context: ssl.SSLContext, url: str) -> Tuple[bool, str, Optional[dict]]:
    try:
        with socket.create_connection((host, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                protocol = ssock.version()

        not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        now = datetime.utcnow()

        if now < not_before or now > not_after:
            return (False, f"SSL certificate expired or not yet valid (Valid from {not_before} to {not_after}).", None)

        supported_protocols = ['TLSv1.2', 'TLSv1.3']
        if protocol not in supported_protocols:
            return (False, f"Unsupported SSL protocol: {protocol}. Supported protocols: {supported_protocols}", None)

        hsts = False
        try:
            response = requests.get(url, timeout=10, verify=True)
            if 'Strict-Transport-Security' in response.headers:
                hsts = True
        except:
            pass

        if not hsts:
            return (False, "HSTS is not enabled.", None)

        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])
        details = {
            'issuer': issuer.get('commonName', ''),
            'subject': subject.get('commonName', ''),
            'protocol': protocol,
            'cipher': cipher,
            'valid_from': not_before.isoformat(),
            'valid_to': not_after.isoformat(),
            'hsts_enabled': hsts
        }
        return (True, "SSL certificate is valid.", details)
    except ssl.SSLError as e:
        return (False, f"SSL error: {e}", None)
    except Exception as e:
        return (False, f"Error in SSL check: {e}", None)

async def check_domain_age(url: str) -> Tuple[bool, str]:
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _check_domain_age, url)
        return result
    except Exception as e:
        return (False, f"Error checking domain age: {e}")

def _check_domain_age(url: str) -> Tuple[bool, str]:
    try:
        domain = urlparse(url).hostname
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            message = "Unable to determine domain creation date."
            logger.warning(message)
            return (False, message)

        age_days = (datetime.now() - creation_date).days
        logger.debug(f"Domain age for {domain}: {age_days} days")

        if age_days < 365:
            message = f"Domain age is {age_days} days, which is relatively new."
            return (False, message)
        else:
            message = f"Domain age is {age_days} days."
            return (True, message)
    except Exception as e:
        message = f"Error checking domain age: {e}"
        logger.error(message)
        return (False, message)

async def check_malware(url: str) -> Tuple[bool, str]:
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, _check_malware, url)
        return result
    except Exception as e:
        return (False, f"Error checking malware: {e}")

def _check_malware(url: str) -> Tuple[bool, str]:
    try:
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            suspicious_links = soup.find_all('a', href=True)
            for link in suspicious_links:
                href = link['href']
                if ('malware' in href.lower() or 'virus' in href.lower()):
                    message = f"Suspicious link detected: {href}"
                    logger.warning(message)
                    return (False, message)

            scripts = soup.find_all('script', src=True)
            for script in scripts:
                src = script['src']
                if ('malware' in src.lower() or 'virus' in src.lower()):
                    message = f"Suspicious script detected: {src}"
                    logger.warning(message)
                    return (False, message)

            return (True, "No malware detected.")
        else:
            message = f"HTTP status code {response.status_code} received."
            logger.warning(message)
            return (False, message)
    except requests.RequestException as e:
        message = f"Request error during malware check: {e}"
        logger.error(message)
        return (False, message)
    except Exception as e:
        message = f"Error checking malware: {e}"
        logger.error(message)
        return (False, message)

async def check_suspicious_tld(url: str) -> Tuple[bool, str]:
    try:
        tld = tldextract.extract(url).suffix
        suspicious_tlds = {'xyz', 'top', 'club', 'tk', 'ga', 'ml', 'cf'}
        logger.debug(f"Domain TLD: {tld}")

        if tld in suspicious_tlds:
            message = f"Suspicious TLD detected: .{tld}"
            logger.warning(message)
            return (False, message)
        else:
            message = f"TLD '.{tld}' is considered safe."
            return (True, message)
    except Exception as e:
        message = f"Error checking TLD: {e}"
        logger.error(message)
        return (False, message)

async def check_phishing_keywords(url: str) -> Tuple[bool, str]:
    try:
        phishing_keywords = {'login', 'update', 'account', 'secure', 'bank', 'verify', 'signin', 'confirm'}
        parsed_url = urlparse(url)
        path = parsed_url.path.lower()
        query = parsed_url.query.lower()

        for keyword in phishing_keywords:
            if (keyword in path or keyword in query):
                message = f"Phishing keyword detected in URL: '{keyword}'."
                logger.warning(message)
                return (False, message)

        return (True, "No phishing keywords found in URL.")
    except Exception as e:
        message = f"Error checking phishing keywords: {e}"
        logger.error(message)
        return (False, message)

async def analyze_form_security(url: str) -> Tuple[bool, str]:
    try:
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')

            if not forms:
                message = "No forms found on the website."
                logger.info(message)
                return (True, message)

            insecure_forms = 0
            for form in forms:
                action = form.get('action', '').lower()
                if action and not action.startswith('https'):
                    insecure_forms += 1
                    logger.warning(f"Insecure form action detected: {action}")

            if insecure_forms > 0:
                message = f"{insecure_forms} insecure form(s) detected."
                return (False, message)
            else:
                message = "All forms are secured with HTTPS."
                return (True, message)
        else:
            message = f"HTTP status code {response.status_code} received."
            logger.warning(message)
            return (False, message)
    except requests.RequestException as e:
        message = f"Request error during form security check: {e}"
        logger.error(message)
        return (False, message)
    except Exception as e:
        message = f"Error analyzing form security: {e}"
        logger.error(message)
        return (False, message)

async def check_persian_content(url: str) -> Tuple[bool, str]:
    try:
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            persian_pattern = re.compile(r'[\u0600-\u06FF]')
            if persian_pattern.search(response.text):
                scam_keywords = ['کلاهبرداری', 'دروغ', 'فریب', 'تقلب', 'هک', 'سرقت']
                scam_detected = any(keyword in response.text for keyword in scam_keywords)
                if scam_detected:
                    message = "Persian content detected with potential scam keywords."
                    logger.info(message)
                    return (False, message)
                else:
                    message = "Persian content detected without scam keywords."
                    logger.info(message)
                    return (True, message)
            else:
                message = "No Persian content found on the website."
                logger.info(message)
                return (False, message)
        else:
            message = f"HTTP status code {response.status_code} received."
            logger.warning(message)
            return (False, message)
    except requests.RequestException as e:
        message = f"Request error during Persian content check: {e}"
        logger.error(message)
        return (False, message)
    except Exception as e:
        message = f"Error checking Persian content: {e}"
        logger.error(message)
        return (False, message)

async def check_contact_privacy_pages(url: str) -> Tuple[bool, str]:
    try:
        response = requests.get(url, timeout=10, verify=False)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            contact = soup.find('a', href=re.compile(r'contact', re.I))
            privacy = soup.find('a', href=re.compile(r'privacy', re.I))
            if (contact and privacy):
                return (True, "Contact and Privacy pages found.")
            else:
                message = "Missing Contact or Privacy pages."
                logger.warning(message)
                return (False, message)
        else:
            message = f"HTTP status code {response.status_code} received."
            logger.warning(message)
            return (False, message)
    except Exception as e:
        message = f"Error checking contact/privacy pages: {e}"
        logger.error(message)
        return (False, message)

async def check_dnssec(url: str) -> Tuple[bool, str]:
    try:
        domain = urlparse(url).hostname
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 5

        try:
            answers = resolver.resolve(domain, 'DNSKEY')
            for rdata in answers:
                if rdata.flags & 0x0100:
                    return (True, "DNSSEC is enabled.")
        except dns.resolver.NoAnswer:
            return (True, "No DNSSEC records found (common for many domains).")
        except dns.resolver.NXDOMAIN:
            return (False, "Domain does not exist.")

        return (True, "Domain exists but DNSSEC status unclear.")
    except Exception as e:
        return (True, f"DNSSEC check skipped: {str(e)}")

async def check_robots_txt(url: str) -> Tuple[bool, str]:
    try:
        parsed_url = urlparse(url)
        robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
        response = requests.get(robots_url, timeout=10, verify=True)
        if response.status_code == 200:
            return (True, "robots.txt found.")
        else:
            return (False, "robots.txt not found.")
    except Exception as e:
        return (False, f"Error checking robots.txt: {e}")

async def check_redirect_chain(url: str) -> Tuple[bool, str]:
    try:
        response = requests.get(url, timeout=10, verify=True, allow_redirects=True)
        if len(response.history) > 3:
            return (False, f"Excessive redirects detected: {len(response.history)}")
        return (True, "No excessive redirects.")
    except Exception as e:
        return (False, f"Error checking redirects: {e}")

async def check_http_security_headers(url: str) -> Tuple[bool, str]:
    try:
        response = requests.get(url, timeout=10, verify=True)
        headers = response.headers
        missing_headers = []
        required_headers = [
            'Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options',
            'X-Frame-Options', 'X-XSS-Protection'
        ]
        for header in required_headers:
            if header not in headers:
                missing_headers.append(header)
        if missing_headers:
            return (False, f"Missing security headers: {', '.join(missing_headers)}")
        return (True, "All important security headers are present.")
    except Exception as e:
        return (False, f"Error checking HTTP security headers: {e}")

async def check_js_obfuscation(url: str) -> Tuple[bool, str]:
    try:
        response = requests.get(url, timeout=10, verify=True)
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script')
        obfuscated_scripts = 0
        for script in scripts:
            if script.string and re.search(r'[a-zA-Z]{30,}', script.string):
                obfuscated_scripts += 1
        if obfuscated_scripts > 0:
            return (False, f"Obfuscated JavaScript detected: {obfuscated_scripts} scripts")
        return (True, "No obfuscated JavaScript detected.")
    except Exception as e:
        return (False, f"Error checking JavaScript obfuscation: {e}")

async def analyze_html_structure(url: str) -> Tuple[bool, str]:
    try:
        response = requests.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        suspicious_patterns = {
            'hidden_elements': len(soup.find_all(style=re.compile(r'display:\s*none|visibility:\s*hidden'))),
            'iframe_count': len(soup.find_all('iframe')),
            'external_scripts': len(soup.find_all('script', src=re.compile(r'^https?://'))),
            'form_actions': [form.get('action') for form in soup.find_all('form')],
            'base_tag': bool(soup.find('base')),
            'meta_redirects': len(soup.find_all('meta', attrs={'http-equiv': 'refresh'}))
        }
        
        warnings = []
        if suspicious_patterns['hidden_elements'] > 5:
            warnings.append(f"Found {suspicious_patterns['hidden_elements']} hidden elements")
        if suspicious_patterns['iframe_count'] > 3:
            warnings.append(f"High number of iframes: {suspicious_patterns['iframe_count']}")
        if suspicious_patterns['base_tag']:
            warnings.append("Base tag detected - possible URL manipulation")
        if suspicious_patterns['meta_redirects']:
            warnings.append("Meta refresh redirects detected")
            
        return (len(warnings) == 0, "\n".join(warnings) if warnings else "HTML structure appears safe")
    except Exception as e:
        return (False, f"Error analyzing HTML: {e}")

async def perform_local_ssl_check(url: str) -> Tuple[bool, str]:
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        context = ssl.create_default_context()
        
        with socket.create_connection((host, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                version = ssock.version()
                
                ssl.match_hostname(cert, host)
                
                if 'publicKey' in cert:
                    key_size = cert['publicKey']['bits']
                    if key_size < 2048:
                        return (False, f"Weak key size detected: {key_size} bits")
                
                if version not in ['TLSv1.2', 'TLSv1.3']:
                    return (False, f"Outdated SSL/TLS version: {version}")
                
                if cipher[2] < 128:
                    return (False, f"Weak cipher strength: {cipher[2]} bits")
                
                return (True, f"Strong SSL configuration detected. Protocol: {version}, Cipher: {cipher[0]}")
    except ssl.CertificateError as e:
        return (False, f"Certificate validation failed: {str(e)}")
    except Exception as e:
        return (False, f"SSL check error: {str(e)}")

async def analyze_network_security(url: str) -> Tuple[bool, str]:
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        
        common_ports = [21, 22, 23, 25, 80, 443, 445, 3389, 8080, 8443]
        open_ports = []
        
        for port in common_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((host, port))
                    if result == 0:
                        open_ports.append(port)
            except:
                continue
        
        dns_issues = []
        try:
            answers = dns.resolver.resolve(host, 'MX')
            if not answers:
                dns_issues.append("No MX records found")
        except:
            dns_issues.append("MX record lookup failed")
            
        try:
            spf = dns.resolver.resolve(host, 'TXT')
            has_spf = any('spf' in str(r).lower() for r in spf)
            if not has_spf:
                dns_issues.append("No SPF record found")
        except:
            dns_issues.append("SPF lookup failed")
            
        try:
            dmarc = dns.resolver.resolve(f"_dmarc.{host}", 'TXT')
            has_dmarc = any('dmarc' in str(r).lower() for r in dmarc)
            if not has_dmarc:
                dns_issues.append("No DMARC record found")
        except:
            dns_issues.append("DMARC lookup failed")
        
        security_issues = []
        if len(open_ports) > 3:
            security_issues.append(f"Multiple open ports detected: {open_ports}")
        if dns_issues:
            security_issues.append(f"DNS security issues: {', '.join(dns_issues)}")
            
        return (len(security_issues) == 0, "\n".join(security_issues) if security_issues else "Network security looks good")
    except Exception as e:
        return (False, f"Network security check error: {e}")

async def check_htaccess(url: str) -> Tuple[bool, str]:
    try:
        parsed_url = urlparse(url)
        htaccess_url = f"{parsed_url.scheme}://{parsed_url.netloc}/.htaccess"
        response = requests.get(htaccess_url, timeout=10, verify=True)
        if response.status_code == 200:
            content = response.text.lower()
            security_directives = ['deny from all', 'options -indexes', 'header set x-frame-options']
            missing_directives = [directive for directive in security_directives if directive not in content]
            if missing_directives:
                return (False, f"Missing security directives in .htaccess: {', '.join(missing_directives)}")
            return (True, "All essential security directives are present in .htaccess.")
        else:
            return (False, ".htaccess file not found.")
    except Exception as e:
        return (False, f"Error checking .htaccess: {e}")

async def check_secure_cookies(url: str) -> Tuple[bool, str]:
    try:
        response = requests.get(url, timeout=10, verify=True)
        cookies = response.cookies
        insecure_cookies = [cookie.name for cookie in cookies if not cookie.secure]
        if insecure_cookies:
            return (False, f"Insecure cookies detected: {', '.join(insecure_cookies)}")
        return (True, "All cookies are secured with Secure flag.")
    except Exception as e:
        return (False, f"Error checking secure cookies: {e}")

async def check_content_security_policy(url: str) -> Tuple[bool, str]:
    try:
        response = requests.get(url, timeout=10, verify=True)
        csp = response.headers.get('Content-Security-Policy')
        if csp:
            return (True, f"CSP is set: {csp}")
        else:
            return (False, "Content Security Policy (CSP) is not set.")
    except Exception as e:
        return (False, f"Error checking CSP: {e}")

async def check_http_methods(url: str) -> Tuple[bool, str]:
    try:
        allowed_methods = []
        methods_to_check = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH']
        for method in methods_to_check:
            try:
                response = requests.request(method, url, timeout=10, verify=True)
                if response.status_code != 405:
                    allowed_methods.append(method)
            except:
                continue

        if 'DELETE' in allowed_methods or 'PUT' in allowed_methods:
            return (False, f"Potentially dangerous HTTP methods allowed: {', '.join(allowed_methods)}")
        return (True, f"Allowed HTTP methods: {', '.join(allowed_methods)}")
    except Exception as e:
        return (False, f"Error checking HTTP methods: {e}")

async def check_ml_model(url: str, model: Pipeline) -> Tuple[bool, str]:
    try:
        prediction = predict(url, model)
        if prediction.lower() == 'scam':
            message = "Machine Learning Model: Scam detected."
            logger.warning(message)
            return (False, message)
        else:
            message = "Machine Learning Model: URL appears safe."
            logger.info(message)
            return (True, message)
    except Exception as e:
        message = f"Error with ML model: {e}"
        logger.error(message)
        return (False, message)

async def check_image_content(url: str) -> Tuple[bool, str]:
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            images = soup.find_all('img', src=True)
            for img in images:
                img_url = img['src']
                if not img_url.startswith('http'):
                    img_url = urlparse(url)._replace(path=img_url).geturl()
                img_response = requests.get(img_url, timeout=10)
                img_bytes = io.BytesIO(img_response.content)
                text = pytesseract.image_to_string(Image.open(img_bytes))
                if re.search(r'login|password|secure', text, re.I):
                    return (False, "Suspicious text detected in images.")
            return (True, "No suspicious text found in images.")
        else:
            return (False, f"HTTP status code {response.status_code} received when accessing URL.")
    except Exception as e:
        return (False, f"Error checking image content: {e}")

MAX_CONCURRENT_SCANS = 5
semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

class HTTPSessionManager:
    def __init__(self, max_sessions: int = 10):
        self.pool = []
        self.max_sessions = max_sessions

    async def get_session(self) -> aiohttp.ClientSession:
        if not self.pool:
            self.pool.append(aiohttp.ClientSession())
        session = self.pool[len(self.pool) % self.max_sessions]
        return session

    async def close_all(self):
        for session in self.pool:
            await session.close()
        self.pool.clear()

session_manager = HTTPSessionManager()

class ScanManager:
    def __init__(self):
        self.running_tasks = set()
        self.is_stopping = False

    def add_task(self, task: asyncio.Task):
        self.running_tasks.add(task)
        task.add_done_callback(self.running_tasks.discard)

    def stop_all(self):
        self.is_stopping = True
        for task in self.running_tasks:
            task.cancel()
        self.running_tasks.clear()

    def reset(self):
        self.is_stopping = False
        self.running_tasks.clear()

scan_manager = ScanManager()

def should_stop() -> bool:
    return scan_manager.is_stopping

class ScanProgress:
    def __init__(self, total_checks: int, callback=None):
        self.total_checks = total_checks
        self.current_progress = 0
        self.callback = callback
        self.weights = {
            'initialization': 5,
            'primary_checks': 60,
            'api_checks': 30,
            'finalization': 5
        }

    def update(self, phase: str, step_progress: float, message: str):
        if phase not in self.weights:
            return

        base_progress = {
            'initialization': 0,
            'primary_checks': 5,
            'api_checks': 65,
            'finalization': 95
        }.get(phase, 0)

        phase_weight = self.weights[phase]
        progress = base_progress + (phase_weight * step_progress)
        self.current_progress = min(99, progress)

        if self.callback:
            self.callback(int(self.current_progress), f"{message} ({int(self.current_progress)}%)")

    def complete(self):
        if self.callback:
            self.callback(100, "Scan complete (100%)")

primary_checks = [
    analyze_ssl_certificate,
    check_domain_age,
    check_malware,
    check_suspicious_tld,
    check_phishing_keywords,
    analyze_form_security,
    check_persian_content,
    check_contact_privacy_pages,
    check_dnssec,
    check_robots_txt,
    check_redirect_chain,
    check_http_security_headers,
    check_js_obfuscation,
    analyze_html_structure,
    perform_local_ssl_check,
    analyze_network_security,
    check_htaccess,
    check_secure_cookies,
    check_content_security_policy,
    check_http_methods,
    check_ml_model,
    check_image_content
]

async def check_with_google_safe_browsing(session: aiohttp.ClientSession, url: str) -> bool:
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('SAFE_BROWSING_KEY')
    try:
        if not GOOGLE_SAFE_BROWSING_API_KEY:
            logger.warning("Google Safe Browsing API key not configured")
            return True
    except Exception as e:
        logger.error(f"Error checking Google Safe Browsing API key: {e}")
        return True

    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {
                "clientId": "scam_detector",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        async with session.post(api_url, json=payload) as response:
            if response.status == 401:
                logger.warning("Invalid Google Safe Browsing API key")
                return True
            response.raise_for_status()
            result = await response.json()
            return "matches" not in result
    except aiohttp.ClientResponseError as e:
        logger.error(f"Error with Google Safe Browsing API: {e.status}, message='{e.message}', url='{e.request_info.url}'")
        return True
    except Exception as e:
        logger.error(f"Error with Google Safe Browsing API: {e}")
        return True

async def check_with_virustotal(session: aiohttp.ClientSession, url: str) -> bool:
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    try:
        if not VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not configured")
            return True
    except Exception as e:
        logger.error(f"Error checking VirusTotal API key: {e}")
        return True

    try:
        api_url = "https://www.virustotal.com/api/v3/urls"
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        async with session.get(f"{api_url}/{url_id}", headers=headers) as response:
            if response.status == 401:
                logger.warning("Invalid VirusTotal API key")
                return True
            elif response.status == 404:
                return True
            elif response.status == 200:
                result = await response.json()
                stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return stats.get('malicious', 0) == 0
            else:
                logger.warning(f"Unexpected status code {response.status} from VirusTotal")
                return True
    except aiohttp.ClientResponseError as e:
        logger.error(f"Error with VirusTotal API: {e.status}, message='{e.message}', url='{e.request_info.url}'")
        return True
    except Exception as e:
        logger.error(f"Error with VirusTotal API: {e}")
        return True

async def check_phishtank(session: aiohttp.ClientSession, url: str) -> Tuple[bool, str]:
    PHISHTANK_API_KEY = os.getenv('PHISHTANK_API_KEY')
    if not PHISHTANK_API_KEY:
        logger.warning("PhishTank API key not configured")
        return (True, "PhishTank API key not configured")

    try:
        api_url = "https://checkurl.phishtank.com/checkurl/"
        payload = {
            'url': url,
            'format': 'json',
            'app_key': PHISHTANK_API_KEY
        }
        async with session.post(api_url, data=payload) as response:
            if response.status == 403:
                logger.warning("PhishTank API returned status code 403")
                return (True, "PhishTank API returned status code 403")
            response.raise_for_status()
            result = await response.json()
            if result.get('results', {}).get('in_database'):
                if result['results'].get('valid'):
                    return (False, "URL is listed in PhishTank as a phishing site.")
            return (True, "URL is not listed in PhishTank.")
    except aiohttp.ClientResponseError as e:
        logger.error(f"Error with PhishTank API: {e.status}, message='{e.message}', url='{e.request_info.url}'")
        return (True, f"Error with PhishTank API: {e}")
    except Exception as e:
        logger.error(f"Error with PhishTank API: {e}")
        return (True, f"Error with PhishTank API: {e}")

async def perform_nmap_scan(domain: str) -> Tuple[bool, str, Optional[dict]]:
    try:
        nm = nmap.PortScanner()
        loop = asyncio.get_event_loop()

        with ThreadPoolExecutor() as executor:
            await loop.run_in_executor(
                executor,
                nm.scan,
                domain,
                '21-25,80,443,8080,8443',
                '-sV --version-intensity 5 -T4'
            )

            results = {
                'open_ports': [],
                'services': {},
                'vulnerabilities': []
            }

            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    ports = nm[host][proto].keys()
                    for port in ports:
                        service = nm[host][proto][port]
                        if service['state'] == 'open':
                            results['open_ports'].append(port)
                            results['services'][port] = {
                                'name': service.get('name', 'unknown'),
                                'version': service.get('version', 'unknown'),
                                'product': service.get('product', 'unknown')
                            }

            message = f"Found {len(results['open_ports'])} open ports"
            return (True, message, results)
    except Exception as e:
        return (False, f"Nmap scan error: {str(e)}", None)

async def check_waf(url: str) -> Tuple[bool, str]:
    try:
        wafw00f = WAFW00F(url)
        waf = await asyncio.get_event_loop().run_in_executor(None, wafw00f.identify_waf)
        if waf:
            return (True, f"WAF detected: {waf[0]}")
        return (False, "No WAF detected")
    except Exception as e:
        return (False, f"WAF check error: {str(e)}")

async def check_shodan_info(domain: str) -> Tuple[bool, str, Optional[dict]]:
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
    if not SHODAN_API_KEY:
        return (True, "Shodan API key not configured.", None)

    try:
        api = Shodan(SHODAN_API_KEY)
        ip = socket.gethostbyname(domain)
        host = await asyncio.get_event_loop().run_in_executor(None, api.host, ip)

        vulns = host.get('vulns', [])
        ports = host.get('ports', [])

        results = {
            'vulns': vulns,
            'ports': ports,
            'os': host.get('os', 'unknown'),
            'organization': host.get('org', 'unknown')
        }

        message = f"Found {len(vulns)} vulnerabilities, {len(ports)} open ports"
        return (True, message, results)
    except Exception as e:
        return (False, f"Shodan lookup error: {str(e)}", None)

async def check_censys_info(domain: str) -> Tuple[bool, str, Optional[dict]]:
    CENSYS_API_ID = os.getenv('CENSYS_API_ID')
    CENSYS_API_SECRET = os.getenv('CENSYS_API_SECRET')
    if not (CENSYS_API_ID and CENSYS_API_SECRET):
        return (True, "Censys API credentials not configured.", None)

    try:
        h = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)
        ip = socket.gethostbyname(domain)
        host_data = await asyncio.get_event_loop().run_in_executor(None, h.view, ip)

        results = {
            'ports': host_data.get('services', []),
            'location': host_data.get('location', {}),
            'autonomous_system': host_data.get('autonomous_system', {})
        }

        return (True, "Censys data retrieved.", results)
    except Exception as e:
        return (False, f"Censys lookup error: {str(e)}", None)

async def check_cve_databases(domain: str) -> Tuple[bool, str, Optional[dict]]:
    try:
        otx_api_key = os.getenv('OTX_API_KEY')
        if not otx_api_key:
            logger.warning("OTX API key not configured")
            return (True, "OTX API key not configured.", None)
        
        otx = OTXv2(otx_api_key)
        results = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, domain)
        
        vulnerabilities = []
        if 'pulse_info' in results:
            for pulse in results['pulse_info']['pulses']:
                for indicator in pulse['indicators']:
                    if indicator['type'] == 'CVE':
                        vulnerabilities.append(indicator['indicator'])
        
        return (len(vulnerabilities) == 0, 
                f"Found {len(vulnerabilities)} CVEs", 
                {'vulnerabilities': vulnerabilities})
    except Exception as e:
        return (False, f"CVE check error: {str(e)}", None)

async def enumerate_subdomains(domain: str) -> Tuple[bool, str, Optional[dict]]:
    try:
        subdomains = set()
        
        try:
            sublist3r_results = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            subdomains.update(sublist3r_results)
        except ValueError as e:
            logger.error(f"Sublist3r error: {e}")
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
        
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT']
        for record in record_types:
            try:
                answers = dns.resolver.resolve(domain, record)
                for rdata in answers:
                    subdomains.add(str(rdata))
            except:
                continue
        
        return (len(subdomains) < 10, 
                f"Found {len(subdomains)} subdomains", 
                {'subdomains': list(subdomains)})
    except Exception as e:
        return (False, f"Subdomain enumeration error: {e}", None)

async def perform_nikto_scan(url: str) -> Tuple[bool, str, Optional[dict]]:
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: subprocess.run(['nikto', '-h', url, '-o', '-', '-Format', 'json'], capture_output=True, text=True)
        )
        if result.returncode != 0:
            raise Exception(result.stderr)
        
        vulnerabilities = json.loads(result.stdout)
        high_severity_vulns = [vuln for vuln in vulnerabilities if vuln.get('severity', 0) >= 2]
        
        return (len(high_severity_vulns) == 0,
                f"Found {len(high_severity_vulns)} high-severity vulnerabilities",
                {'vulnerabilities': high_severity_vulns})
    except Exception as e:
        return (False, f"Nikto scan error: {str(e)}", None)

async def check_cdn_usage(url: str) -> Tuple[bool, str, Optional[dict]]:
    try: 
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        cdn_info = {
            'provider': None,
            'cname_records': [],
            'headers': {},
            'security_features': []
        }

        cdn_patterns = {
            'cloudflare': r'(.+)?cloudflare\.com$',
            'akamai': r'(.+)?akamai(edge|zed)?\.net$',
            'fastly': r'(.+)?fastly\.net$',
            'cloudfront': r'(.+)?cloudfront\.net$',
            'cdn77': r'(.+)?cdn77\.org$',
            'maxcdn': r'(.+)?maxcdn\.com$',
            'belugacdn': r'(.+)?belugacdn\.com$',
            'bunnycdn': r'(.+)?b-cdn\.net$',
            'sucuri': r'(.+)?sucuri\.net$'
        }

        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: dns.resolver.resolve(domain, 'CNAME')
            )
            for rdata in answers:
                cdn_info['cname_records'].append(str(rdata.target))
                for cdn, pattern in cdn_patterns.items():
                    if re.search(pattern, str(rdata.target), re.I):
                        cdn_info['provider'] = cdn
                        break
        except Exception:
            pass

        try:
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: requests.get(url, timeout=10)
            )
            headers = response.headers

            cdn_headers = {
                'CF-Ray': 'Cloudflare',
                'X-CDN': 'Generic CDN',
                'X-Fastly-Request-ID': 'Fastly',
                'X-Akamai-Transformed': 'Akamai',
                'X-CDN77': 'CDN77',
                'X-Edge-Location': 'Generic CDN',
                'X-Cache': 'Generic CDN',
                'X-Amz-Cf-Id': 'CloudFront',
                'X-Sucuri-ID': 'Sucuri'
            }

            for header, cdn in cdn_headers.items():
                if (header in headers):
                    cdn_info['headers'][header] = headers[header]
                    if not cdn_info['provider']:
                        cdn_info['provider'] = cdn

            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'X-Content-Type-Options': 'NoSniff',
                'X-XSS-Protection': 'XSS Protection',
                'X-Frame-Options': 'Frame Options',
                'Content-Security-Policy': 'CSP'
            }

            for header, feature in security_headers.items():
                if (header in headers):
                    cdn_info['security_features'].append(feature)

        except Exception as e:
            logger.warning(f"Error checking headers: {e}")

        if (cdn_info['provider'] or cdn_info['cname_records'] or cdn_info['headers']):
            message = f"CDN detected: {cdn_info['provider'] or 'Unknown provider'}"
            if cdn_info['security_features']:
                message += f"\nSecurity features: {', '.join(cdn_info['security_features'])}"
            return (True, message, cdn_info)
        
        return (False, "No CDN detected", cdn_info)
    except Exception as e:
        return (False, f"CDN usage check error: {e}", None)

api_checks = [
    check_with_google_safe_browsing,
    check_with_virustotal,
    check_phishtank,
    check_shodan_info,
    check_censys_info,
    check_cve_databases,
    enumerate_subdomains,
    perform_nikto_scan,
    check_cdn_usage
]

def calculate_risk_score(results: dict) -> int:
    try:
        risk_factors = {
            'analyze_ssl_certificate': 20,
            'check_domain_age': 15,
            'check_malware': 25,
            'check_suspicious_tld': 20,
            'check_phishing_keywords': 20,
            'analyze_form_security': 15,
            'check_persian_content': 10,
            'check_contact_privacy_pages': 10,
            'check_dnssec': 15,
            'check_robots_txt': 5,
            'check_image_content': 15,
            'check_redirect_chain': 15,
            'check_http_security_headers': 20,
            'check_js_obfuscation': 20,
            'analyze_html_structure': 15,
            'perform_local_ssl_check': 20,
            'analyze_network_security': 20,
            'check_htaccess': 15,
            'check_secure_cookies': 15,
            'check_content_security_policy': 15,
            'check_http_methods': 15,
            'check_with_google_safe_browsing': 5,
            'check_with_virustotal': 5,
            'check_phishtank': 5,
            'check_shodan_info': 5,
            'check_censys_info': 5,
            'check_cve_databases': 5,
            'enumerate_subdomains': 5,
            'perform_nikto_scan': 5,
            'check_cdn_usage': 5
        }
        
        security_analysis = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': []
        }
        
        score = 0
        for key, value in results.items():
            status = value[0] if isinstance(value, tuple) else value
            if not status:
                risk_value = risk_factors.get(key, 0)
                score += risk_value
                
                if risk_value >= 20:
                    security_analysis['critical'].append((key, value[1] if isinstance(value, tuple) else "Check failed"))
                elif risk_value >= 15:
                    security_analysis['high'].append((key, value[1] if isinstance(value, tuple) else "Check failed"))
                elif risk_value >= 10:
                    security_analysis['medium'].append((key, value[1] if isinstance(value, tuple) else "Check failed"))
                else:
                    security_analysis['low'].append((key, value[1] if isinstance(value, tuple) else "Check failed"))

        max_score = sum(risk_factors.values())
        normalized_score = min(int((score / max_score) * 100), 100)

        logger.debug(f"Security Analysis Summary:")
        logger.debug(f"Critical Issues: {len(security_analysis['critical'])}")
        logger.debug(f"High Risk Issues: {len(security_analysis['high'])}")
        logger.debug(f"Medium Risk Issues: {len(security_analysis['medium'])}")
        logger.debug(f"Low Risk Issues: {len(security_analysis['low'])}")
        logger.debug(f"Final Risk Score: {normalized_score}%")

        return normalized_score, security_analysis
    except Exception as e:
        logger.error(f"Risk score calculation failed: {e}")
        return 100, {'critical': [], 'high': [], 'medium': [], 'low': []}

def generate_recommendations(risk_score: int, persian_content_message: str) -> List[str]:
    recommendations = []
    if risk_score >= 70:
        recommendations.append("اخطار: ریسک کلاهبرداری بالا! از وارد کردن اطلاعات شخصی خودداری کنید.")
    elif 40 <= risk_score < 70:
        recommendations.append("هشدار: ریسک کلاهبرداری متوسط. مراقب باشید.")
    else:
        recommendations.append("ریسک کلاهبرداری کم. اما همیشه احتیاط لازم است.")

    if "Persian content detected" in persian_content_message or "Persian" in persian_content_message:
        recommendations.append("محتوای فارسی شناسایی شده. با احتیاط از این سایت استفاده کنید.")

    return recommendations

def format_scan_result(result: dict) -> str:
    try:
        risk_score, security_analysis = result.get('risk_score', (100, {}))
        formatted_result = [
            f"نتیجه اسکن: {result.get('status', 'Unknown')}",
            f"امتیاز ریسک: {risk_score}%",
            f"آدرس: {result.get('url', 'N/A')}",
            f"زمان: {result.get('timestamp', 'N/A')}",
            "\nتحلیل امنیتی جامع:"
        ]

        if security_analysis.get('critical'):
            formatted_result.append("\nمشکلات بحرانی:")
            for issue, detail in security_analysis['critical']:
                formatted_result.append(f"  ⚠️ {issue.replace('_', ' ').title()}")
                formatted_result.append(f"    جزئیات: {detail}")

        if security_analysis.get('high'):
            formatted_result.append("\nمشکلات با ریسک بالا:")
            for issue, detail in security_analysis['high']:
                formatted_result.append(f"  ❗ {issue.replace('_', ' ').title()}")
                formatted_result.append(f"    جزئیات: {detail}")

        if security_analysis.get('medium'):
            formatted_result.append("\nمشکلات با ریسک متوسط:")
            for issue, detail in security_analysis['medium']:
                formatted_result.append(f"  ⚡ {issue.replace('_', ' ').title()}")
                formatted_result.append(f"    جزئیات: {detail}")

        if security_analysis.get('low'):
            formatted_result.append("\nمشکلات با ریسک پایین:")
            for issue, detail in security_analysis['low']:
                formatted_result.append(f"  ℹ️ {issue.replace('_', ' ').title()}")
                formatted_result.append(f"    جزئیات: {detail}")

        recommendations = result.get('recommendations', [])
        formatted_result.append("\nتوصیه‌های امنیتی:")
        for recommendation in recommendations:
            formatted_result.append(f"  - {recommendation}")

        return "\n".join(formatted_result)
    except Exception as e:
        logger.error(f"Error formatting scan result: {e}")
        return "خطا در فرمت‌بندی نتایج اسکن."

async def scan_site(url: str, model: Optional[Pipeline] = None, 
                    progress_callback=None, stop_check=None, 
                    selected_tools=None) -> dict:
    selected_tools = selected_tools or {}
    
    available_tools = {}
    try:
        if selected_tools.get('nikto'):
            try:
                subprocess.run(['nikto', '-version'], capture_output=True, check=True)
                available_tools['nikto'] = True
            except:
                available_tools['nikto'] = False
                logger.warning("Nikto not found in system")
        
        if selected_tools.get('nmap'):
            try:
                subprocess.run(['nmap', '-V'], capture_output=True, check=True)
                available_tools['nmap'] = True
            except:
                available_tools['nmap'] = False
                logger.warning("Nmap not found in system")

        selected_tools.update(available_tools)
    except Exception as e:
        logger.error(f"Error checking tool availability: {e}")
    
    tool_to_check_mapping = {
        'nikto': perform_nikto_scan,
        'nmap': perform_nmap_scan,
        'subdomains': enumerate_subdomains,
        'cve': check_cve_databases,
        'shodan': check_shodan_info
    }
    
    filtered_api_checks = [
        check for tool, check in tool_to_check_mapping.items()
        if selected_tools.get(tool, False)
    ]
    
    basic_api_checks = [
        check for check in api_checks
        if check not in tool_to_check_mapping.values()
    ]
    
    active_api_checks = basic_api_checks + filtered_api_checks
    
    try:
        scan_manager.reset()
        results = {}
        total_checks = len(primary_checks) + len(api_checks)
        progress = ScanProgress(total_checks=total_checks, callback=progress_callback)

        if not url or not isinstance(url, str):
            raise ValueError("Invalid URL input")

        if not validate_url(url):
            raise ValueError(f"Invalid URL format: {url}")

        progress.update('initialization', 0.5, "Initializing scan...")
        progress.update('initialization', 1.0, "Checking cache...")

        if url in cache:
            logger.info("Cache hit. Returning cached results.")
            return cache[url]

        async with semaphore:
            async with aiohttp.ClientSession() as session:
                logger.info("Starting primary security checks...")
                for i, check in enumerate(primary_checks):
                    if stop_check and stop_check():
                        raise asyncio.CancelledError("Scan stopped by user")

                    progress.update('primary_checks', i / len(primary_checks), f"Running primary check: {check.__name__}")

                    try:
                        if check.__name__ == 'check_ml_model':
                            result = await check(url, model)
                        elif check.__name__ in ['check_with_google_safe_browsing', 'check_with_virustotal', 'check_phishtank']:
                            result = await check(session, url)
                        else:
                            result = await check(url)
                        results[check.__name__] = result
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        logger.error(f"Error in primary check {check.__name__}: {str(e)}")
                        results[check.__name__] = (False, f"{check.__name__} check failed: {str(e)}")

                progress.update('api_checks', 0, "Starting API checks...")
                logger.info("Starting additional API checks...")
                for i, check in enumerate(active_api_checks):
                    if stop_check and stop_check():
                        break

                    progress.update('api_checks', i / len(active_api_checks), f"Running API check: {check.__name__}")

                    try:
                        if check.__name__ in ['check_with_google_safe_browsing', 'check_with_virustotal', 'check_phishtank']:
                            result = await check(session, url)
                        elif check.__name__ in [func.__name__ for func in [check_shodan_info, check_censys_info, check_cve_databases, enumerate_subdomains, perform_nikto_scan]]:
                            parsed_url = urlparse(url)
                            domain = parsed_url.hostname
                            if check.__name__ in ['check_shodan_info', 'check_censys_info', 'check_cve_databases', 'enumerate_subdomains', 'perform_nikto_scan']:
                                if check.__name__ == 'perform_nikto_scan':
                                    result = await check(url)
                                else:
                                    result = await check(domain)
                            else:
                                result = await check(url)
                        else:
                            result = await check(url)
                        results[check.__name__] = result
                    except asyncio.CancelledError:
                        raise
                    except Exception as e:
                        logger.warning(f"API check {check.__name__} failed: {str(e)}")
                        results[check.__name__] = (True, f"API check failed: {str(e)}")

        progress.update('finalization', 0.3, "Calculating final results...")
        risk_score, security_analysis = calculate_risk_score(results)
        persian_content_message = results.get('check_persian_content', (False, ""))[1]
        recommendations = generate_recommendations(risk_score, persian_content_message)

        progress.update('finalization', 0.6, "Preparing final report...")
        final_result = {
            'status': 'success',
            'risk_score': (risk_score, security_analysis),
            'checks': {k: v[0] if isinstance(v, tuple) else v for k, v in results.items()},
            'details': {k: v[1] if isinstance(v, tuple) and len(v) > 1 else "" for k, v in results.items()},
            'recommendations': recommendations,
            'timestamp': datetime.now().isoformat(),
            'url': url
        }

        progress.update('finalization', 0.9, "Saving results to cache...")
        cache[url] = final_result
        save_cache_entry(url, final_result)

        progress.complete()
        return final_result

    except asyncio.CancelledError:
        logger.info("Scan interrupted by user.")
        return {
            'status': 'stopped',
            'error': 'Scan stopped by user',
            'risk_score': calculate_risk_score(results) if results else 0,
            'timestamp': datetime.now().isoformat(),
            'url': url
        }
    except Exception as e:
        logger.error(f"Unexpected error during scan: {e}")
        return {
            'status': 'error',
            'error': f"Unexpected error during scan: {e}",
            'risk_score': calculate_risk_score(results) if results else 0,
            'timestamp': datetime.now().isoformat(),
            'url': url
        }
    finally:
        scan_manager.stop_all()

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Scan a website for potential scams and security issues.')
    parser.add_argument('url', type=str, help='URL of the website to scan')
    parser.add_argument('--train', action='store_true', help='Train the machine learning model')
    args = parser.parse_args()

    if args.train:
        train_model()
    else:
        try:
            scanned_result = asyncio.run(scan_site(args.url, model))
            print(format_scan_result(scanned_result))
        except Exception as e:
            logger.error(f"Unexpected error during scan: {e}")
            error_result = {
                'status': 'error',
                'error': f"Unexpected error during scan: {e}",
                'risk_score': 100,
                'timestamp': datetime.now().isoformat(),
                'url': args.url
            }
            print(format_scan_result(error_result))
