from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                            QTabWidget, QTextEdit, QFileDialog, QTreeWidget, 
                            QTreeWidgetItem, QMessageBox, QProgressBar,
                            QCheckBox, QGroupBox, QGridLayout, QSplitter, QScrollArea, QSizePolicy, QFrame)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QPalette, QColor, QFont
import pyqtgraph as pg
import numpy as np
import asyncio
from scanner import scan_site
import json
from datetime import datetime
import sys
import logging
import darkdetect

logger = logging.getLogger(__name__)

class ScanWorker(QThread):
    finished = pyqtSignal(dict)
    progress = pyqtSignal(int, str)
    
    def __init__(self, url, model, selected_tools=None):
        super().__init__()
        self.url = url
        self.model = model
        self.selected_tools = selected_tools or {}
        self.is_running = True
        
    def stop(self):
        self.is_running = False
        
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                scan_site(self.url, self.model, 
                         progress_callback=self.progress.emit,
                         stop_check=lambda: not self.is_running,
                         selected_tools=self.selected_tools)
            )
            loop.close()
            self.finished.emit(result)
        except Exception as e:
            self.finished.emit({
                'status': 'error',
                'error': str(e),
                'risk_score': 100,
                'timestamp': datetime.now().isoformat(),
                'url': self.url
            })

class ScamDetectorGUI(QMainWindow):
    def __init__(self, model=None):
        super().__init__()
        self.model = model
        self.setup_ui()
        self.apply_theme()
        
    def apply_theme(self):
        is_dark = darkdetect.isDark()
        palette = QPalette()
        
        if is_dark:
            palette.setColor(QPalette.ColorRole.Window, QColor(30, 30, 30))
            palette.setColor(QPalette.ColorRole.WindowText, QColor(0, 255, 0))
            palette.setColor(QPalette.ColorRole.Base, QColor(20, 20, 20))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(30, 30, 30))
            palette.setColor(QPalette.ColorRole.Text, QColor(0, 255, 0))
            palette.setColor(QPalette.ColorRole.Button, QColor(30, 30, 30))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor(0, 255, 0))
            palette.setColor(QPalette.ColorRole.Link, QColor(0, 255, 0))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 255, 0))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor(30, 30, 30))
        else:
            palette.setColor(QPalette.ColorRole.Window, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.WindowText, QColor(0, 128, 0))
            palette.setColor(QPalette.ColorRole.Base, QColor(255, 255, 255))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(245, 245, 245))
            palette.setColor(QPalette.ColorRole.Text, QColor(0, 128, 0))
            palette.setColor(QPalette.ColorRole.Button, QColor(240, 240, 240))
            palette.setColor(QPalette.ColorRole.ButtonText, QColor(0, 128, 0))
            palette.setColor(QPalette.ColorRole.Link, QColor(0, 128, 0))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 128, 0))
            palette.setColor(QPalette.ColorRole.HighlightedText, QColor(240, 240, 240))

        self.setPalette(palette)
        
        # Style sheets
        self.setStyleSheet("""
            QFrame {
                border-radius: 8px;
                padding: 10px;
                background-color: palette(base);
            }
            QPushButton {
                border-radius: 5px;
                padding: 8px 15px;
                background-color: #006400;
                color: white;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #008000;
            }
            QPushButton:pressed {
                background-color: #004d00;
            }
            QLineEdit {
                border-radius: 5px;
                padding: 8px;
                border: 1px solid palette(mid);
            }
            QProgressBar {
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #006400;
                border-radius: 5px;
            }
            QTextEdit {
                border-radius: 5px;
                padding: 10px;
            }
        """)

    def setup_ui(self):
        self.setWindowTitle("v7lthronyx ScamDetection نسخه ی اول بتا")
        self.setGeometry(100, 100, 1200, 800)
        
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        tabs = QTabWidget()
        
        self.scan_tab = QWidget()
        self.results_tab = QWidget()
        self.batch_scan_tab = QWidget()
        self.expert_tab = QWidget()
        
        self.setup_scan_tab()
        self.setup_results_tab()
        self.setup_batch_scan_tab()
        self.setup_expert_tab()
        
        tabs.addTab(self.scan_tab, "🎯 Scan Configuration")
        tabs.addTab(self.results_tab, "📊 Analysis Results")
        tabs.addTab(self.expert_tab, "🔬 Expert Analysis")
        tabs.addTab(self.batch_scan_tab, "🔍 Batch Scan")
        
        self.tabs = tabs
        layout.addWidget(tabs)

    def setup_scan_tab(self):
        layout = QVBoxLayout(self.scan_tab)
        
        header = QLabel("CYBER THREAT SCANNER")
        header.setStyleSheet("font-size: 24px; color: #00ff00; margin: 10px;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)
        
        input_widget = QFrame()
        input_widget.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        input_layout = QHBoxLayout(input_widget)
        
        url_label = QLabel("TARGET URL:")
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL to scan...")
        self.url_input.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.url_input.setMinimumHeight(40)
        
        self.scan_button = QPushButton("▶ START SCAN")
        self.scan_button.setMinimumHeight(40)
        self.scan_button.setMinimumWidth(100)
        self.scan_button.clicked.connect(self.start_scan)
        
        self.stop_button = QPushButton("⬛ STOP")
        self.stop_button.setEnabled(False)
        
        self.stop_button.clicked.connect(self.stop_scan)
        
        input_layout.addWidget(url_label)
        input_layout.addWidget(self.url_input)
        input_layout.addWidget(self.scan_button)
        input_layout.addWidget(self.stop_button)
        layout.addWidget(input_widget)
        
        tools_group = QGroupBox("Advanced Tools (Optional)")
        tools_layout = QGridLayout()
        
        self.tool_selections = {
            'nikto': QCheckBox("Nikto Web Scanner"),
            'nmap': QCheckBox("Nmap Port Scanner"),
            'subdomains': QCheckBox("Subdomain Enumeration"),
            'cve': QCheckBox("CVE Database Check"),
            'wayback': QCheckBox("Wayback Machine Check"),
            'shodan': QCheckBox("Shodan Analysis")
        }
        
        tooltips = {
            'nikto': "Comprehensive web server scanner",
            'nmap': "Network port and service scanner",
            'subdomains': "Discover website subdomains",
            'cve': "Check known vulnerabilities",
            'wayback': "Historical site analysis",
            'shodan': "IoT and server exposure analysis"
        }
        
        row, col = 0, 0
        for key, checkbox in self.tool_selections.items():
            checkbox.setToolTip(tooltips[key])
            tools_layout.addWidget(checkbox, row, col)
            col += 1
            if col > 2:
                col = 0
                row += 1
        
        tools_group.setLayout(tools_layout)
        layout.addWidget(tools_group)
        
        control_widget = QWidget()
        control_layout = QHBoxLayout(control_widget)
        
        control_layout.addWidget(self.scan_button)
        control_layout.addWidget(self.stop_button)
        layout.addWidget(control_widget)
        
        progress_frame = QFrame()
        progress_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        progress_layout = QVBoxLayout(progress_frame)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setFormat("%p% - %v/%m checks completed")
        self.progress_bar.setMinimumHeight(30)
        layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel()
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.status_label)
        
        layout.addStretch()

    def setup_results_tab(self):
        layout = QVBoxLayout(self.results_tab)
        
        stats_group = QGroupBox("Scan Statistics")
        stats_layout = QGridLayout()
        
        self.risk_score_label = QLabel("Risk Score: -")
        self.scan_time_label = QLabel("Scan Time: -")
        self.total_checks_label = QLabel("Total Checks: -")
        self.failed_checks_label = QLabel("Failed Checks: -")
        
        stats_layout.addWidget(self.risk_score_label, 0, 0)
        stats_layout.addWidget(self.scan_time_label, 0, 1)
        stats_layout.addWidget(self.total_checks_label, 1, 0)
        stats_layout.addWidget(self.failed_checks_label, 1, 1)
        
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        graphs_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        threat_group = QGroupBox("Threat Analysis")
        threat_layout = QVBoxLayout()
        self.graph_widget = pg.PlotWidget()
        self.setup_threat_graph(self.graph_widget)
        threat_layout.addWidget(self.graph_widget)
        threat_group.setLayout(threat_layout)
        
        category_group = QGroupBox("Risk Distribution")
        category_layout = QVBoxLayout()
        self.category_graph = pg.PlotWidget()
        self.setup_category_graph(self.category_graph)
        category_layout.addWidget(self.category_graph)
        category_group.setLayout(category_layout)
        
        graphs_splitter.addWidget(threat_group)
        graphs_splitter.addWidget(category_group)
        layout.addWidget(graphs_splitter)
        
        results_group = QGroupBox("Detailed Analysis")
        results_layout = QVBoxLayout()
        
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_widget = QWidget()
        scroll_layout = QVBoxLayout(scroll_widget)
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        self.result_text.setMinimumHeight(400)
        scroll_layout.addWidget(self.result_text)
        
        scroll_area.setWidget(scroll_widget)
        results_layout.addWidget(scroll_area)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        export_button = QPushButton("📑 Export Report")
        export_button.clicked.connect(self.export_results)
        layout.addWidget(export_button)

    def setup_batch_scan_tab(self):
        layout = QVBoxLayout(self.batch_scan_tab)
        
        import_button = QPushButton("Import URLs from File")
        import_button.clicked.connect(self.import_urls)
        
        self.batch_tree = QTreeWidget()
        self.batch_tree.setHeaderLabels(["URL", "Risk Score", "Status"])
        self.batch_tree.setColumnWidth(0, 400)
        
        layout.addWidget(import_button)
        layout.addWidget(self.batch_tree)

    def setup_expert_tab(self):
        layout = QVBoxLayout(self.expert_tab)
        
        tech_group = QGroupBox("Technical Analysis Report")
        tech_layout = QVBoxLayout()
        
        self.expert_text = QTextEdit()
        self.expert_text.setReadOnly(True)
        self.expert_text.setMinimumHeight(300)
        tech_layout.addWidget(self.expert_text)
        
        tech_group.setLayout(tech_layout)
        layout.addWidget(tech_group)
        
        export_group = QGroupBox("Export Options")
        export_layout = QHBoxLayout()
        
        pdf_btn = QPushButton("📑 Export as PDF")
        pdf_btn.clicked.connect(self.export_expert_pdf)
        
        json_btn = QPushButton("🔧 Export as JSON")
        json_btn.clicked.connect(self.export_expert_json)
        
        xml_btn = QPushButton("📋 Export as XML")
        xml_btn.clicked.connect(self.export_expert_xml)
        
        export_layout.addWidget(pdf_btn)
        export_layout.addWidget(json_btn)
        export_layout.addWidget(xml_btn)
        
        export_group.setLayout(export_layout)
        layout.addWidget(export_group)

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Warning", "Please enter a website URL.")
            return
        
        try:
            from urllib.parse import urlparse
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                QMessageBox.warning(self, "Warning", "Invalid URL format. Please enter a complete URL (e.g., https://example.com)")
                return
            
            selected_tools = {
                tool: checkbox.isChecked()
                for tool, checkbox in self.tool_selections.items()
            }
            
            self.result_text.clear()
            self.result_text.append("Scanning...")
            
            self.progress_bar.setValue(0)
            self.progress_bar.setMaximum(100)
            self.status_label.setText("Starting scan...")
            self.scan_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            
            self.scan_worker = ScanWorker(url, self.model, selected_tools)
            self.scan_worker.finished.connect(self.handle_scan_result)
            self.scan_worker.progress.connect(self.update_progress)
            self.scan_worker.start()
            
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error starting scan: {str(e)}")

    def stop_scan(self):
        if hasattr(self, 'scan_worker'):
            self.scan_worker.stop()
            self.status_label.setText("Stopping scan...")
            self.stop_button.setEnabled(False)

    def update_progress(self, percent, task):
        self.progress_bar.setValue(percent)
        self.status_label.setText(task)

    def handle_scan_result(self, result):
        self.tabs.setCurrentIndex(1)
        
        self.last_result = result
        
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100)
        self.status_label.setText("Scan complete")
        
        if result['status'] == 'success':
            self.risk_score_label.setText(f"Risk Score: {result['risk_score']}%")
            self.scan_time_label.setText(f"Scan Time: {result['timestamp']}")
            total_checks = len(result['checks'])
            failed_checks = sum(1 for v in result['checks'].values() if not v)
            self.total_checks_label.setText(f"Total Checks: {total_checks}")
            self.failed_checks_label.setText(f"Failed Checks: {failed_checks}")
            
            try:
                self.update_detailed_graph(result)
            except Exception as e:
                logger.error(f"Error updating graphs: {e}")
                QMessageBox.warning(self, "Warning", "Error updating visualization graphs")
            
            self.result_text.clear()
        
            if result['status'] == 'success':
                self.result_text.append("🔍 === تحلیل امنیتی جامع === 🔍\n")
                self.result_text.append(f"📊 امتیاز ریسک کلی: {result['risk_score']}%")
                self.result_text.append(f"🌐 دامنه: {result['url']}")
                self.result_text.append(f"⏱️ زمان اسکن: {result['timestamp']}\n")
                
                details = result.get('details', {})
                
                if 'ssl_cert' in details:
                    self.result_text.append("\n🔐 جزئیات گواهینامه SSL:")
                    ssl_details = details['ssl_cert']
                    if isinstance(ssl_details, dict):
                        self.result_text.append(f"  • صادرکننده: {ssl_details.get('issuer', 'N/A')}")
                        self.result_text.append(f"  • تاریخ اعتبار: {ssl_details.get('valid_from', 'N/A')} تا {ssl_details.get('valid_to', 'N/A')}")
                        self.result_text.append(f"  • پروتکل: {ssl_details.get('protocol', 'N/A')}")
                        self.result_text.append(f"  • رمزنگاری: {ssl_details.get('cipher', 'N/A')}")
    
                if 'domain_age' in details:
                    self.result_text.append("\n🌍 تحلیل دامنه:")
                    self.result_text.append(f"  • {details['domain_age']}")
                
                if 'security_headers' in details:
                    self.result_text.append("\n🛡️ هدرهای امنیتی:")
                    self.result_text.append(f"  • {details['security_headers']}")
    
                check_categories = {
                    '🔒 امنیت زیرساخت': {
                        'checks': ['ssl_cert', 'security_headers', 'form_security', 'dnssec', 'waf_check', 'cdn_check'],
                        'description': 'تحلیل امنیت پایه‌ای سرور و پروتکل‌ها'
                    },
                    '🖥️ زیرساخت شبکه': {
                        'checks': ['nmap_scan', 'shodan_info', 'censys_info'],
                        'description': 'بررسی پورت‌های باز و سرویس‌های در معرض'
                    },
                    '📄 محتوا و اسکریپت‌ها': {
                        'checks': ['persian_content', 'image_content', 'js_obfuscation'],
                        'description': 'تحلیل محتوا و کدهای مشکوک'
                    },
                    '🌐 اعتبارسنجی دامنه': {
                        'checks': ['domain_age', 'suspicious_tld', 'domain_reputation'],
                        'description': 'بررسی اعتبار و سابقه دامنه'
                    },
                    '⚠️ تهدیدات': {
                        'checks': ['malware', 'phishing_keywords', 'google_safe_browsing', 'virustotal'],
                        'description': 'شناسایی تهدیدات و بدافزارها'
                    },
                    '🔄 ناوبری و دسترسی': {
                        'checks': ['redirect_chain', 'robots_txt', 'contact_privacy'],
                        'description': 'بررسی مسیرهای هدایت و دسترسی‌ها'
                    }
                }
                
                checks = result['checks']
                self.result_text.append("\n📋 === نتایج تفصیلی === 📋")
                
                for category, info in check_categories.items():
                    self.result_text.append(f"\n{category}:")
                    self.result_text.append(f"توضیحات: {info['description']}")
                    
                    category_results = {k: checks[k] for k in info['checks'] if k in checks}
                    passed = sum(1 for v in category_results.values() if v)
                    total = len(category_results)
                    score = (passed / total) * 100 if total > 0 else 0
                    
                    self.result_text.append(f"امتیاز: {score:.1f}% ({passed}/{total})")
                    
                    for check in info['checks']:
                        if check in checks:
                            status = "✅ قبول" if checks[check] else "❌ رد"
                            detail = details.get(check, "")
                            check_name = check.replace('_', ' ').title()
                            self.result_text.append(f"  • {check_name}: {status}")
                            if detail:
                                self.result_text.append(f"    💡 {detail}")
    
                if 'nmap_scan' in details:
                    self.result_text.append("\n🔍 جزئیات اسکن پورت:")
                    nmap_details = details['nmap_scan']
                    if isinstance(nmap_details, dict):
                        for port, info in nmap_details.get('services', {}).items():
                            self.result_text.append(f"  • پورت {port}: {info.get('name')} {info.get('version')}")
    
                if any(k for k in details if 'vuln' in k.lower()):
                    self.result_text.append("\n⚠️ آسیب‌پذیری‌های شناسایی شده:")
                    for key, value in details.items():
                        if 'vuln' in key.lower():
                            self.result_text.append(f"  • {value}")
    
                self.result_text.append("\n🎯 === توصیه‌های امنیتی === 🎯")
                recommendations = result.get('recommendations', [])
                priorities = ['بحرانی', 'مهم', 'متوسط', 'کم']
                for priority in priorities:
                    priority_recs = [r for r in recommendations if priority in r]
                    if priority_recs:
                        self.result_text.append(f"\n{priority}:")
                        for rec in priority_recs:
                            self.result_text.append(f"• {rec}")
    
            else:
                self.result_text.append(f"❌ خطا: {result.get('error', 'مشکل در اسکن')}")
    
            self.update_expert_analysis(result)

    def update_detailed_graph(self, result):
        try:
            self.graph_widget.clear()
            self.category_graph.clear()
            
            if not result.get('checks'):
                return
            
            check_categories = {
                '🔒 امنیت زیرساخت': {
                    'checks': {
                        'analyze_ssl_certificate': {
                            'weight': 10,
                            'critical': True,
                            'dependencies': ['check_https']
                        },
                        'check_http_security_headers': {
                            'weight': 8,
                            'critical': True,
                            'dependencies': []
                        },
                        'check_secure_cookies': {
                            'weight': 7,
                            'critical': False,
                            'dependencies': []
                        },
                        'check_content_security_policy': {
                            'weight': 8,
                            'critical': True,
                            'dependencies': []
                        }
                    },
                    'weight': 30,
                    'threshold': 0.8
                },
                '🖥️ شبکه و سرویس‌ها': {
                    'checks': {
                        'perform_nmap_scan': {
                            'weight': 10,
                            'critical': True,
                            'dependencies': []
                        },
                        'check_shodan_info': {
                            'weight': 8,
                            'critical': False,
                            'dependencies': []
                        },
                        'check_censys_info': {
                            'weight': 7,
                            'critical': False,
                            'dependencies': []
                        },
                        'check_cdn_usage': {
                            'weight': 5,
                            'critical': False,
                            'dependencies': []
                        }
                    },
                    'weight': 20,
                    'threshold': 0.7
                },
                '📄 محتوا و کدها': {
                    'checks': {
                        'check_js_obfuscation': {
                            'weight': 9,
                            'critical': True,
                            'dependencies': []
                        },
                        'check_persian_content': {
                            'weight': 7,
                            'critical': False,
                            'dependencies': []
                        },
                        'check_image_content': {
                            'weight': 6,
                            'critical': False,
                            'dependencies': []
                        }
                    },
                    'weight': 15,
                    'threshold': 0.6
                },
                '🌐 دامنه و DNS': {
                    'checks': {
                        'check_domain_age': {
                            'weight': 9,
                            'critical': True,
                            'dependencies': []
                        },
                        'check_suspicious_tld': {
                            'weight': 8,
                            'critical': True,
                            'dependencies': []
                        },
                        'check_dnssec': {
                            'weight': 7,
                            'critical': False,
                            'dependencies': []
                        }
                    },
                    'weight': 20,
                    'threshold': 0.75
                }
            }

            checks = result['checks']
            details = result.get('details', {})
            
            category_scores = {}
            for category, info in check_categories.items():
                category_checks = info['checks']
                valid_checks = []
                total_weight = 0
                weighted_score = 0
                
                for check_name, check_info in category_checks.items():
                    if check_name in checks:
                        dependencies_met = all(
                            dep in checks and checks[dep] 
                            for dep in check_info['dependencies']
                        )
                        
                        if dependencies_met:
                            valid_checks.append(check_name)
                            weight = check_info['weight']
                            total_weight += weight
                            
                            check_score = 1.0 if checks[check_name] else 0.0
                            if not checks[check_name] and check_info['critical']:
                                check_score = 0.0
                            
                            if check_name in details:
                                detail_text = str(details[check_name]).lower()
                                if 'critical' in detail_text:
                                    check_score *= 0.5
                                elif 'warning' in detail_text:
                                    check_score *= 0.8
                            
                            weighted_score += check_score * weight
                
                if total_weight > 0:
                    final_score = weighted_score / total_weight
                    if final_score < info['threshold']:
                        final_score *= 0.8
                    
                    category_scores[category] = {
                        'score': final_score,
                        'valid_checks': len(valid_checks),
                        'total_checks': len(category_checks),
                        'weight': info['weight']
                    }
            
            self._draw_bar_chart(category_scores, result['risk_score'])
            
            self._draw_pie_chart(category_scores)
            
        except Exception as e:
            logger.error(f"Error in update_detailed_graph: {e}")
            raise

    def _draw_bar_chart(self, category_scores, risk_score):
        x = np.arange(len(category_scores))
        bars = []
        for i, (category, data) in enumerate(category_scores.items()):
            score = data['score']
            color = self.get_risk_color(score)
            
            bar = pg.BarGraphItem(
                x=[i], height=[score],
                width=0.8,
                brush=color,
                pen=pg.mkPen('w', width=1),
                name=category
            )
            self.graph_widget.addItem(bar)
            bars.append(bar)
            
            details = f"{score*100:.1f}%\n{data['valid_checks']}/{data['total_checks']}"
            if score < 0.6:
                details += "\n⚠️ نیاز به بررسی"
            text = pg.TextItem(
                text=details,
                color='w',
                anchor=(0.5, 0)
            )
            text.setPos(i, score)
            self.graph_widget.addItem(text)
        
        self.graph_widget.setTitle(
            f"Security Analysis (Overall Risk Score: {risk_score}%)",
            color='#00ff00',
            size='12pt'
        )
        self.graph_widget.setLabel('left', 'Security Score', units='%')
        self.graph_widget.setLabel('bottom', 'Security Categories')
        
        threshold_line = pg.InfiniteLine(
            pos=0.7,
            angle=0,
            pen=pg.mkPen('r', style=Qt.PenStyle.DashLine),
            label='Security Threshold'
        )
        self.graph_widget.addItem(threshold_line)

    def _draw_pie_chart(self, category_scores):
        pass

    def get_risk_color(self, score):
        if score >= 0.9:
            return pg.mkBrush('#00ff00')
        elif score >= 0.8:
            return pg.mkBrush('#7fff00')
        elif score >= 0.7:
            return pg.mkBrush('#ffff00')
        elif score >= 0.6:
            return pg.mkBrush('#ffa500')
        elif score >= 0.4:
            return pg.mkBrush('#ff4500')
        else:
            return pg.mkBrush('#ff0000')

    def import_urls(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Import URLs", "", "Text Files (*.txt);;All Files (*)")
        if file_path:
            try:
                with open(file_path, 'r') as file:
                    urls = [line.strip() for line in file if line.strip()]
                for url in urls:
                    item = QTreeWidgetItem([url, "", "Pending"])
                    self.batch_tree.addTopLevelItem(item)
                self.batch_scan()
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error importing URLs: {str(e)}")

    def batch_scan(self):
        root = self.batch_tree.invisibleRootItem()
        selected_tools = {
            tool: checkbox.isChecked()
            for tool, checkbox in self.tool_selections.items()
        }
        for i in range(root.childCount()):
            item = root.child(i)
            if item.text(2) == "Pending":
                url = item.text(0)
                worker = ScanWorker(url, self.model, selected_tools)
                worker.finished.connect(lambda result, item=item: self.handle_batch_result(result, item))
                worker.start()

    def handle_batch_result(self, result, item):
        if result['status'] == 'success':
            item.setText(1, str(result['risk_score']))
            item.setText(2, "Completed")
        else:
            item.setText(2, "Error")

    def export_results(self):
        if hasattr(self, 'last_result'):
            file_path, _ = QFileDialog.getSaveFileName(
                self, 
                "Export Report",
                f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                "Text Files (*.txt);;All Files (*)"
            )
            if file_path:
                try:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(self.result_text.toPlainText())
                    QMessageBox.information(self, "Success", "Report exported successfully!")
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to export report: {str(e)}")

    def setup_threat_graph(self, graph_widget):
        graph_widget.setBackground(None)
        graph_widget.showGrid(x=True, y=True, alpha=0.3)
        graph_widget.setTitle("Security Check Results", color='#00ff00', size='12pt')
        graph_widget.setLabel('left', 'Score', color='#00ff00')
        graph_widget.setLabel('bottom', 'Categories', color='#00ff00')
        graph_widget.getPlotItem().setDownsampling(mode='peak')
        graph_widget.getPlotItem().setClipToView(True)
        graph_widget.setYRange(0, 1)

    def setup_category_graph(self, graph_widget):
        graph_widget.setBackground(None)
        graph_widget.showGrid(False)
        graph_widget.setTitle("Risk Distribution", color='#00ff00', size='12pt')
        graph_widget.hideAxis('left')
        graph_widget.hideAxis('bottom')
        graph_widget.setAspectLocked(True)
        graph_widget.setRange(xRange=(-150, 150), yRange=(-150, 150))

    def update_expert_analysis(self, result):
        try:
            if not result or result['status'] != 'success':
                return
            
            expert_details = [
                "=== DETAILED TECHNICAL ANALYSIS REPORT ===\n",
                f"Scan Timestamp: {result['timestamp']}",
                f"Target URL: {result['url']}",
                f"Overall Risk Score: {result['risk_score']}%\n"
            ]

            if 'ssl_cert' in result.get('details', {}):
                ssl_details = result['details']['ssl_cert']
                expert_details.extend([
                    "=== SSL/TLS CONFIGURATION ===",
                    f"Protocol Version: {ssl_details.get('protocol')}",
                    f"Cipher Suite: {ssl_details.get('cipher')}",
                    f"Certificate Issuer: {ssl_details.get('issuer')}",
                    f"Certificate Validity: {ssl_details.get('valid_from')} to {ssl_details.get('valid_to')}",
                    f"HSTS Enabled: {ssl_details.get('hsts_enabled', False)}\n"
                ])

            if 'nmap_scan' in result.get('details', {}):
                nmap_details = result['details']['nmap_scan']
                expert_details.extend([
                    "=== NETWORK SECURITY ANALYSIS ===",
                    "Open Ports and Services:"
                ])
                for port, info in nmap_details.get('services', {}).items():
                    expert_details.append(
                        f"  Port {port}: {info.get('name')} {info.get('version')} - {info.get('product')}"
                    )
                expert_details.append("")

            headers = result.get('details', {}).get('security_headers', {})
            if headers:
                expert_details.extend([
                    "=== SECURITY HEADERS ANALYSIS ===",
                    f"Content-Security-Policy: {headers.get('csp', 'Not Set')}",
                    f"X-Frame-Options: {headers.get('x_frame_options', 'Not Set')}",
                    f"X-XSS-Protection: {headers.get('x_xss_protection', 'Not Set')}",
                    f"X-Content-Type-Options: {headers.get('x_content_type_options', 'Not Set')}\n"
                ])

            vulns = result.get('details', {}).get('vulnerabilities', [])
            if vulns:
                expert_details.extend([
                    "=== VULNERABILITY ANALYSIS ===",
                    "Identified Vulnerabilities:"
                ])
                for vuln in vulns:
                    expert_details.extend([
                        f"  - Type: {vuln.get('type', 'Unknown')}",
                        f"    Severity: {vuln.get('severity', 'Unknown')}",
                        f"    Description: {vuln.get('description', 'No description')}\n"
                    ])

            waf_info = result.get('details', {}).get('waf_info', {})
            if waf_info:
                expert_details.extend([
                    "=== WAF ANALYSIS ===",
                    f"WAF Detected: {waf_info.get('detected', False)}",
                    f"WAF Type: {waf_info.get('type', 'Unknown')}",
                    f"WAF Version: {waf_info.get('version', 'Unknown')}\n"
                ])

            dns_info = result.get('details', {}).get('dns_security', {})
            if dns_info:
                expert_details.extend([
                    "=== DNS SECURITY ANALYSIS ===",
                    f"DNSSEC Enabled: {dns_info.get('dnssec', False)}",
                    f"SPF Record: {dns_info.get('spf', 'Not Found')}",
                    f"DMARC Record: {dns_info.get('dmarc', 'Not Found')}",
                    f"MX Records: {', '.join(dns_info.get('mx', []))}\n"
                ])

            expert_details.extend([
                "=== TECHNICAL RECOMMENDATIONS ===",
                "Priority Fixes:",
                "1. Critical Security Issues:",
                "   - " + "\n   - ".join(result.get('recommendations', [])),
                "\n2. Security Optimizations:",
                "   - Implement recommended security headers",
                "   - Enable DNSSEC if not enabled",
                "   - Configure CSP with strict rules",
                "   - Enable HSTS preloading\n"
            ])

            expert_details.extend([
                "=== RAW SECURITY CHECK RESULTS ===",
                "Individual Check Results:"
            ])
            
            for check, status in result['checks'].items():
                detail = result['details'].get(check, "No additional details")
                expert_details.append(f"  {check}:")
                expert_details.append(f"    Status: {'Pass' if status else 'Fail'}")
                expert_details.append(f"    Details: {detail}\n")

            self.expert_text.setText("\n".join(expert_details))

        except Exception as e:
            logger.error(f"Error generating expert analysis: {e}")
            self.expert_text.setText(f"Error generating expert analysis: {str(e)}")

    def export_expert_pdf(self):
        if hasattr(self, 'last_result'):
            try:
                file_path, _ = QFileDialog.getSaveFileName(
                    self,
                    "Export Expert Analysis",
                    f"expert_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    "PDF Files (*.pdf)"
                )
                if file_path:
                    QMessageBox.information(self, "Success", "Expert analysis exported as PDF!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export PDF: {str(e)}")

    def export_expert_json(self):
        if hasattr(self, 'last_result'):
            try:
                file_path, _ = QFileDialog.getSaveFileName(
                    self,
                    "Export Expert Analysis",
                    f"expert_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    "JSON Files (*.json)"
                )
                if file_path:
                    with open(file_path, 'w', encoding='utf-8') as f:
                        json.dump(self.last_result, f, ensure_ascii=False, indent=2)
                    QMessageBox.information(self, "Success", "Expert analysis exported as JSON!")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export JSON: {str(e)}")

    def export_expert_xml(self):
        pass

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # Adjust font sizes based on window size
        window_width = self.width()
        if window_width < 800:
            self.setFont(QFont('Vazir', 8))
        elif window_width < 1200:
            self.setFont(QFont('Vazir', 10))
        else:
            self.setFont(QFont('Vazir', 12))

def main():
    app = QApplication(sys.argv)
    app.setStyle('Fusion')
    window = ScamDetectorGUI()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
