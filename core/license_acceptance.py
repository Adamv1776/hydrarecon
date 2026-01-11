#!/usr/bin/env python3
"""
HydraRecon - License Acceptance and Legal Disclaimer
This module must be run on first launch to ensure user accepts terms.
"""

import os
import sys
import json
import hashlib
from datetime import datetime
from pathlib import Path


class LicenseAcceptance:
    """Handles license acceptance and legal compliance"""
    
    DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   ██╗  ██╗██╗   ██╗██████╗ ██████╗  █████╗ ██████╗ ███████╗ ██████╗ ██████╗  ║
║   ██║  ██║╚██╗ ██╔╝██╔══██╗██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗ ║
║   ███████║ ╚████╔╝ ██║  ██║██████╔╝███████║██████╔╝█████╗  ██║     ██║   ██║ ║
║   ██╔══██║  ╚██╔╝  ██║  ██║██╔══██╗██╔══██║██╔══██╗██╔══╝  ██║     ██║   ██║ ║
║   ██║  ██║   ██║   ██████╔╝██║  ██║██║  ██║██║  ██║███████╗╚██████╗╚██████╔╝ ║
║   ╚═╝  ╚═╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝  ║
║                                                                              ║
║            Enterprise Security Assessment Suite v1.0                         ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   ⚠️  IMPORTANT LEGAL NOTICE - PLEASE READ CAREFULLY  ⚠️                      ║
║                                                                              ║
║   This software contains powerful security assessment tools designed         ║
║   EXCLUSIVELY for AUTHORIZED security testing and research.                  ║
║                                                                              ║
║   ┌────────────────────────────────────────────────────────────────────────┐ ║
║   │  UNAUTHORIZED USE OF THIS SOFTWARE MAY VIOLATE FEDERAL, STATE, AND    │ ║
║   │  INTERNATIONAL LAWS. VIOLATORS MAY BE SUBJECT TO CRIMINAL PENALTIES   │ ║
║   │  INCLUDING FINES AND IMPRISONMENT.                                    │ ║
║   └────────────────────────────────────────────────────────────────────────┘ ║
║                                                                              ║
║   By using HydraRecon, you certify that:                                     ║
║                                                                              ║
║   ✓ You have WRITTEN AUTHORIZATION to test target systems                   ║
║   ✓ You will use this software ONLY for legal, authorized purposes          ║
║   ✓ You understand and accept the LICENSE and DISCLAIMER                    ║
║   ✓ You accept FULL RESPONSIBILITY for your actions                         ║
║   ✓ You will comply with ALL applicable laws and regulations                ║
║                                                                              ║
║   Intended uses:                                                             ║
║   • Authorized penetration testing with written permission                   ║
║   • Security assessments of systems you own or are authorized to test        ║
║   • Educational research in controlled environments                          ║
║   • Bug bounty programs with defined scope                                   ║
║   • Compliance auditing (PCI-DSS, HIPAA, SOC2, ISO 27001)                   ║
║                                                                              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║   For full license terms, see: LICENSE                                       ║
║   For detailed disclaimer, see: DISCLAIMER.md                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""

    AGREEMENT_TEXT = """
I CERTIFY THAT:

1. I have read and understand the LICENSE and DISCLAIMER documents
2. I will use HydraRecon ONLY for authorized security testing
3. I have or will obtain WRITTEN AUTHORIZATION before testing any system
4. I understand that unauthorized use is a CRIMINAL OFFENSE
5. I accept full legal responsibility for my use of this software
6. I agree to comply with all applicable laws and ethical guidelines
7. I understand the developers are NOT liable for any misuse
"""

    def __init__(self):
        self.config_dir = Path.home() / ".hydrarecon"
        self.acceptance_file = self.config_dir / "license_accepted.json"
        
    def check_acceptance(self) -> bool:
        """Check if user has previously accepted the license"""
        if not self.acceptance_file.exists():
            return False
        
        try:
            with open(self.acceptance_file, 'r') as f:
                data = json.load(f)
                
            # Verify the acceptance hash
            expected_hash = self._generate_acceptance_hash(
                data.get('username', ''),
                data.get('timestamp', '')
            )
            
            if data.get('hash') == expected_hash:
                return True
        except (json.JSONDecodeError, KeyError):
            pass
        
        return False
    
    def _generate_acceptance_hash(self, username: str, timestamp: str) -> str:
        """Generate a hash for acceptance verification"""
        content = f"HYDRARECON_ACCEPTED:{username}:{timestamp}"
        return hashlib.sha256(content.encode()).hexdigest()
    
    def record_acceptance(self, username: str):
        """Record that the user has accepted the license"""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().isoformat()
        acceptance_hash = self._generate_acceptance_hash(username, timestamp)
        
        data = {
            "version": "1.0",
            "software": "HydraRecon",
            "username": username,
            "timestamp": timestamp,
            "hash": acceptance_hash,
            "accepted_terms": [
                "LICENSE",
                "DISCLAIMER.md",
                "Authorized use only",
                "Legal compliance",
                "Full responsibility accepted"
            ]
        }
        
        with open(self.acceptance_file, 'w') as f:
            json.dump(data, f, indent=2)
    
    def show_disclaimer_gui(self) -> bool:
        """Show disclaimer in GUI mode and get acceptance"""
        try:
            from PyQt6.QtWidgets import (
                QApplication, QDialog, QVBoxLayout, QTextEdit, 
                QCheckBox, QPushButton, QLabel, QHBoxLayout, QLineEdit
            )
            from PyQt6.QtCore import Qt
            from PyQt6.QtGui import QFont
            
            app = QApplication.instance()
            if not app:
                app = QApplication(sys.argv)
            
            dialog = QDialog()
            dialog.setWindowTitle("HydraRecon - License Agreement")
            dialog.setMinimumSize(800, 700)
            dialog.setStyleSheet("""
                QDialog {
                    background-color: #0a0e14;
                }
                QTextEdit {
                    background-color: #161b22;
                    color: #c9d1d9;
                    border: 1px solid #30363d;
                    border-radius: 6px;
                    font-family: 'Consolas', 'Monaco', monospace;
                    font-size: 11px;
                    padding: 10px;
                }
                QCheckBox {
                    color: #c9d1d9;
                    font-size: 13px;
                    spacing: 8px;
                }
                QCheckBox::indicator {
                    width: 18px;
                    height: 18px;
                }
                QLabel {
                    color: #c9d1d9;
                }
                QLineEdit {
                    background-color: #161b22;
                    color: #c9d1d9;
                    border: 1px solid #30363d;
                    border-radius: 4px;
                    padding: 8px;
                    font-size: 13px;
                }
                QPushButton {
                    background-color: #238636;
                    color: white;
                    border: none;
                    border-radius: 6px;
                    padding: 12px 24px;
                    font-weight: bold;
                    font-size: 14px;
                }
                QPushButton:hover {
                    background-color: #2ea043;
                }
                QPushButton:disabled {
                    background-color: #21262d;
                    color: #484f58;
                }
                QPushButton#decline {
                    background-color: #da3633;
                }
                QPushButton#decline:hover {
                    background-color: #f85149;
                }
            """)
            
            layout = QVBoxLayout(dialog)
            layout.setSpacing(16)
            layout.setContentsMargins(24, 24, 24, 24)
            
            # Disclaimer text
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            text_edit.setPlainText(self.DISCLAIMER + "\n" + self.AGREEMENT_TEXT)
            layout.addWidget(text_edit)
            
            # Name input
            name_layout = QHBoxLayout()
            name_label = QLabel("Your Full Name:")
            name_label.setFont(QFont("Segoe UI", 11))
            name_input = QLineEdit()
            name_input.setPlaceholderText("Enter your full legal name")
            name_layout.addWidget(name_label)
            name_layout.addWidget(name_input)
            layout.addLayout(name_layout)
            
            # Checkboxes
            check1 = QCheckBox("I have read and understand the LICENSE and DISCLAIMER")
            check2 = QCheckBox("I certify I will only use this software for AUTHORIZED, LEGAL purposes")
            check3 = QCheckBox("I accept FULL LEGAL RESPONSIBILITY for my use of this software")
            check4 = QCheckBox("I understand unauthorized use may result in CRIMINAL PROSECUTION")
            
            layout.addWidget(check1)
            layout.addWidget(check2)
            layout.addWidget(check3)
            layout.addWidget(check4)
            
            # Buttons
            btn_layout = QHBoxLayout()
            
            decline_btn = QPushButton("Decline & Exit")
            decline_btn.setObjectName("decline")
            decline_btn.clicked.connect(dialog.reject)
            
            accept_btn = QPushButton("I Accept - Launch HydraRecon")
            accept_btn.setEnabled(False)
            accept_btn.clicked.connect(dialog.accept)
            
            def update_accept_btn():
                all_checked = (
                    check1.isChecked() and check2.isChecked() and 
                    check3.isChecked() and check4.isChecked() and
                    len(name_input.text().strip()) >= 2
                )
                accept_btn.setEnabled(all_checked)
            
            check1.stateChanged.connect(update_accept_btn)
            check2.stateChanged.connect(update_accept_btn)
            check3.stateChanged.connect(update_accept_btn)
            check4.stateChanged.connect(update_accept_btn)
            name_input.textChanged.connect(update_accept_btn)
            
            btn_layout.addWidget(decline_btn)
            btn_layout.addStretch()
            btn_layout.addWidget(accept_btn)
            layout.addLayout(btn_layout)
            
            result = dialog.exec()
            
            if result == QDialog.DialogCode.Accepted:
                self.record_acceptance(name_input.text().strip())
                return True
            
            return False
            
        except ImportError:
            # Fall back to console mode
            return self.show_disclaimer_console()
    
    def show_disclaimer_console(self) -> bool:
        """Show disclaimer in console mode and get acceptance"""
        print(self.DISCLAIMER)
        print(self.AGREEMENT_TEXT)
        print("\n" + "="*80)
        
        name = input("\nEnter your full name to certify acceptance: ").strip()
        
        if len(name) < 2:
            print("\n❌ Invalid name. License not accepted.")
            return False
        
        print(f"\n{name}, do you accept these terms? (Type 'I ACCEPT' to continue)")
        response = input("> ").strip()
        
        if response.upper() == "I ACCEPT":
            self.record_acceptance(name)
            print("\n✅ License accepted. You may now use HydraRecon.")
            print("   Remember: Use responsibly and legally.")
            return True
        else:
            print("\n❌ License not accepted. Exiting.")
            return False


def check_license_on_startup() -> bool:
    """
    Check license acceptance on application startup.
    Returns True if accepted, False otherwise.
    """
    license_checker = LicenseAcceptance()
    
    if license_checker.check_acceptance():
        return True
    
    # Try GUI first, fall back to console
    try:
        return license_checker.show_disclaimer_gui()
    except Exception:
        return license_checker.show_disclaimer_console()


if __name__ == "__main__":
    if check_license_on_startup():
        print("\n✅ Ready to launch HydraRecon")
        sys.exit(0)
    else:
        print("\n❌ License not accepted")
        sys.exit(1)
