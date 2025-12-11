"""
EDR Evasion Page
Advanced endpoint detection evasion interface
"""

import asyncio
import os
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QTabWidget, QComboBox,
    QSpinBox, QGroupBox, QTextEdit, QLineEdit, QProgressBar,
    QSplitter, QFrame, QHeaderView, QCheckBox, QMessageBox,
    QFileDialog, QListWidget, QListWidgetItem, QFormLayout,
    QPlainTextEdit, QTreeWidget, QTreeWidgetItem
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QThread
from PyQt6.QtGui import QColor, QFont

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from core.edr_evasion import (
    EDREvasion, EvasionTechnique, EDRProduct, DetectionVector,
    EDRProfile, HookInfo, PayloadWrapper
)


class EDRWorker(QThread):
    """Background worker for EDR operations"""
    result_ready = pyqtSignal(object)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    
    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs
    
    def run(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.func(*self.args, **self.kwargs))
            self.result_ready.emit(result)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            loop.close()


class EDREvasionPage(QWidget):
    """EDR Evasion GUI Page"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.evasion = EDREvasion()
        self.workers = []
        self.current_payload = b""
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        layout = QVBoxLayout(self)
        layout.setSpacing(10)
        
        # Header
        header = QLabel("🛡️ EDR Evasion Framework")
        header.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #ff6600;
            padding: 10px;
        """)
        layout.addWidget(header)
        
        # Warning
        warning = QLabel("⚠️ FOR AUTHORIZED PENETRATION TESTING ONLY")
        warning.setStyleSheet("""
            background: #ff660022;
            border: 2px solid #ff6600;
            color: #ff6600;
            padding: 10px;
            border-radius: 4px;
            font-weight: bold;
        """)
        warning.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(warning)
        
        # Main tabs
        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 2px solid #333;
                border-radius: 8px;
            }
            QTabBar::tab {
                background: #1a1a2e;
                color: #888;
                padding: 10px 20px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }
            QTabBar::tab:selected {
                background: #ff6600;
                color: #000;
            }
        """)
        
        tabs.addTab(self.create_detection_tab(), "🔍 EDR Detection")
        tabs.addTab(self.create_hooks_tab(), "🪝 Hook Analysis")
        tabs.addTab(self.create_techniques_tab(), "⚔️ Evasion Techniques")
        tabs.addTab(self.create_loader_tab(), "📦 Loader Generator")
        tabs.addTab(self.create_syscall_tab(), "📞 Direct Syscalls")
        
        layout.addWidget(tabs)
        
        # Status bar
        self.status_bar = QLabel("EDR Evasion Framework Ready")
        self.status_bar.setStyleSheet("""
            background: #1a1a2e;
            padding: 8px;
            border-radius: 4px;
            color: #ff6600;
        """)
        layout.addWidget(self.status_bar)
    
    def create_detection_tab(self) -> QWidget:
        """Create EDR detection tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Detection controls
        controls_group = QGroupBox("EDR Detection")
        controls_group.setStyleSheet("""
            QGroupBox { font-weight: bold; border: 2px solid #ff6600; border-radius: 8px; margin-top: 10px; padding-top: 10px; }
            QGroupBox::title { color: #ff6600; }
        """)
        controls_layout = QVBoxLayout(controls_group)
        
        detect_btn = QPushButton("🔍 Detect Installed EDRs")
        detect_btn.clicked.connect(self.detect_edr)
        detect_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #ff6600, #ff9900);
                color: #000;
                font-weight: bold;
                padding: 15px;
                font-size: 14px;
            }
        """)
        controls_layout.addWidget(detect_btn)
        
        layout.addWidget(controls_group)
        
        # Detected EDRs
        edrs_group = QGroupBox("Detected EDR Products")
        edrs_layout = QVBoxLayout(edrs_group)
        
        self.edr_table = QTableWidget()
        self.edr_table.setColumnCount(5)
        self.edr_table.setHorizontalHeaderLabels([
            "Product", "Processes", "Drivers", "Services", "Bypass Count"
        ])
        self.edr_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.edr_table.itemDoubleClicked.connect(self.show_edr_details)
        edrs_layout.addWidget(self.edr_table)
        
        layout.addWidget(edrs_group)
        
        # Detection capabilities
        caps_group = QGroupBox("Detection Capabilities")
        caps_layout = QHBoxLayout(caps_group)
        
        self.capability_cards = {}
        capabilities = [
            ("Userland Hooks", "hooks", "#ff0044"),
            ("Kernel Callbacks", "kernel", "#ff6600"),
            ("ETW Telemetry", "etw", "#ffaa00"),
            ("Memory Scanning", "memory", "#00ccff"),
            ("Behavior Analysis", "behavior", "#ff00ff"),
        ]
        
        for name, key, color in capabilities:
            card = QFrame()
            card.setStyleSheet(f"""
                QFrame {{
                    background: linear-gradient(135deg, {color}22, {color}44);
                    border: 2px solid {color};
                    border-radius: 8px;
                    padding: 10px;
                }}
            """)
            card_layout = QVBoxLayout(card)
            
            status = QLabel("❓")
            status.setStyleSheet(f"font-size: 24px;")
            status.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            label = QLabel(name)
            label.setStyleSheet("font-size: 11px; color: #888;")
            label.setAlignment(Qt.AlignmentFlag.AlignCenter)
            
            card_layout.addWidget(status)
            card_layout.addWidget(label)
            
            self.capability_cards[key] = status
            caps_layout.addWidget(card)
        
        layout.addWidget(caps_group)
        
        # Recommendations
        recs_group = QGroupBox("Recommended Evasion Techniques")
        recs_layout = QVBoxLayout(recs_group)
        
        self.recommendations_list = QListWidget()
        self.recommendations_list.setStyleSheet("""
            QListWidget {
                background: #0d0d1a;
                border: 1px solid #333;
            }
            QListWidget::item {
                padding: 8px;
                border-bottom: 1px solid #222;
            }
        """)
        recs_layout.addWidget(self.recommendations_list)
        
        layout.addWidget(recs_group)
        
        return widget
    
    def create_hooks_tab(self) -> QWidget:
        """Create hook analysis tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Hook detection
        detection_group = QGroupBox("Hook Detection")
        detection_layout = QFormLayout(detection_group)
        
        self.target_module = QComboBox()
        self.target_module.addItems([
            "ntdll.dll",
            "kernel32.dll",
            "kernelbase.dll",
            "user32.dll",
            "ws2_32.dll"
        ])
        detection_layout.addRow("Target Module:", self.target_module)
        
        detect_hooks_btn = QPushButton("🪝 Detect Hooks")
        detect_hooks_btn.clicked.connect(self.detect_hooks)
        detect_hooks_btn.setStyleSheet("background: #ff6600; color: #000; font-weight: bold; padding: 10px;")
        detection_layout.addRow("", detect_hooks_btn)
        
        layout.addWidget(detection_group)
        
        # Detected hooks
        hooks_group = QGroupBox("Detected Hooks")
        hooks_layout = QVBoxLayout(hooks_group)
        
        self.hooks_table = QTableWidget()
        self.hooks_table.setColumnCount(5)
        self.hooks_table.setHorizontalHeaderLabels([
            "Function", "Module", "Hook Type", "EDR Hook", "Original Bytes"
        ])
        self.hooks_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        hooks_layout.addWidget(self.hooks_table)
        
        layout.addWidget(hooks_group)
        
        # Unhooking
        unhook_group = QGroupBox("Unhooking")
        unhook_layout = QVBoxLayout(unhook_group)
        
        unhook_info = QLabel("""
Unhooking restores the original function bytes by reading a clean copy
from disk and overwriting the hooked function in memory.
        """)
        unhook_info.setWordWrap(True)
        unhook_info.setStyleSheet("color: #888; padding: 10px;")
        unhook_layout.addWidget(unhook_info)
        
        unhook_btn = QPushButton("🔓 Generate Unhooking Code")
        unhook_btn.clicked.connect(self.generate_unhook_code)
        unhook_layout.addWidget(unhook_btn)
        
        self.unhook_code = QPlainTextEdit()
        self.unhook_code.setReadOnly(True)
        self.unhook_code.setMaximumHeight(200)
        self.unhook_code.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ff88;
            }
        """)
        unhook_layout.addWidget(self.unhook_code)
        
        layout.addWidget(unhook_group)
        
        return widget
    
    def create_techniques_tab(self) -> QWidget:
        """Create evasion techniques tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Technique categories
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left: Technique list
        left = QWidget()
        left_layout = QVBoxLayout(left)
        
        techniques_group = QGroupBox("Evasion Techniques")
        techniques_layout = QVBoxLayout(techniques_group)
        
        self.techniques_list = QListWidget()
        for tech in EvasionTechnique:
            item = QListWidgetItem(f"⚔️ {tech.value.replace('_', ' ').title()}")
            item.setData(Qt.ItemDataRole.UserRole, tech)
            self.techniques_list.addItem(item)
        self.techniques_list.itemClicked.connect(self.show_technique)
        techniques_layout.addWidget(self.techniques_list)
        
        left_layout.addWidget(techniques_group)
        splitter.addWidget(left)
        
        # Right: Technique details and code
        right = QWidget()
        right_layout = QVBoxLayout(right)
        
        details_group = QGroupBox("Technique Details")
        details_layout = QVBoxLayout(details_group)
        
        self.technique_desc = QLabel("Select a technique to view details")
        self.technique_desc.setWordWrap(True)
        self.technique_desc.setStyleSheet("color: #888; padding: 10px;")
        details_layout.addWidget(self.technique_desc)
        
        right_layout.addWidget(details_group)
        
        # Code generation
        code_group = QGroupBox("Generated Code")
        code_layout = QVBoxLayout(code_group)
        
        gen_btn = QPushButton("⚡ Generate Code")
        gen_btn.clicked.connect(self.generate_technique_code)
        gen_btn.setStyleSheet("background: #00ccff; color: #000; font-weight: bold;")
        code_layout.addWidget(gen_btn)
        
        self.technique_code = QPlainTextEdit()
        self.technique_code.setReadOnly(True)
        self.technique_code.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ff88;
            }
        """)
        code_layout.addWidget(self.technique_code)
        
        copy_btn = QPushButton("📋 Copy Code")
        copy_btn.clicked.connect(self.copy_technique_code)
        code_layout.addWidget(copy_btn)
        
        right_layout.addWidget(code_group)
        splitter.addWidget(right)
        
        splitter.setSizes([300, 600])
        layout.addWidget(splitter)
        
        return widget
    
    def create_loader_tab(self) -> QWidget:
        """Create loader generator tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Payload input
        payload_group = QGroupBox("Payload Configuration")
        payload_layout = QFormLayout(payload_group)
        
        # Payload source
        payload_input_layout = QHBoxLayout()
        self.payload_path = QLineEdit()
        self.payload_path.setPlaceholderText("Path to shellcode file or paste hex...")
        payload_input_layout.addWidget(self.payload_path)
        
        browse_btn = QPushButton("📂")
        browse_btn.clicked.connect(self.browse_payload)
        payload_input_layout.addWidget(browse_btn)
        
        payload_layout.addRow("Payload:", payload_input_layout)
        
        # Output format
        self.loader_format = QComboBox()
        self.loader_format.addItems(["Python", "PowerShell", "C#", "C/C++"])
        payload_layout.addRow("Output Format:", self.loader_format)
        
        layout.addWidget(payload_group)
        
        # Evasion selection
        evasion_group = QGroupBox("Select Evasion Techniques")
        evasion_layout = QVBoxLayout(evasion_group)
        
        self.technique_checkboxes = {}
        techniques_grid = QHBoxLayout()
        
        row1 = QVBoxLayout()
        for tech in [EvasionTechnique.ETW_PATCHING, EvasionTechnique.AMSI_BYPASS, 
                     EvasionTechnique.MEMORY_ENCRYPTION, EvasionTechnique.SLEEP_OBFUSCATION]:
            cb = QCheckBox(tech.value.replace("_", " ").title())
            cb.setChecked(True)
            self.technique_checkboxes[tech] = cb
            row1.addWidget(cb)
        techniques_grid.addLayout(row1)
        
        row2 = QVBoxLayout()
        for tech in [EvasionTechnique.DIRECT_SYSCALL, EvasionTechnique.UNHOOKING,
                     EvasionTechnique.PPID_SPOOFING, EvasionTechnique.STACK_SPOOFING]:
            cb = QCheckBox(tech.value.replace("_", " ").title())
            self.technique_checkboxes[tech] = cb
            row2.addWidget(cb)
        techniques_grid.addLayout(row2)
        
        evasion_layout.addLayout(techniques_grid)
        
        generate_btn = QPushButton("📦 Generate Evasive Loader")
        generate_btn.clicked.connect(self.generate_loader)
        generate_btn.setStyleSheet("""
            QPushButton {
                background: linear-gradient(135deg, #ff6600, #ff0044);
                color: #fff;
                font-weight: bold;
                padding: 15px;
                font-size: 14px;
            }
        """)
        evasion_layout.addWidget(generate_btn)
        
        layout.addWidget(evasion_group)
        
        # Output
        output_group = QGroupBox("Generated Loader")
        output_layout = QVBoxLayout(output_group)
        
        # Success rate
        rate_layout = QHBoxLayout()
        rate_layout.addWidget(QLabel("Estimated Success Rate:"))
        self.success_rate = QProgressBar()
        self.success_rate.setStyleSheet("""
            QProgressBar {
                border: 2px solid #333;
                border-radius: 5px;
                background: #1a1a2e;
                height: 20px;
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ff0044, stop:0.5 #ff6600, stop:1 #00ff88);
            }
        """)
        rate_layout.addWidget(self.success_rate)
        output_layout.addLayout(rate_layout)
        
        self.loader_output = QPlainTextEdit()
        self.loader_output.setReadOnly(True)
        self.loader_output.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #ff6600;
            }
        """)
        output_layout.addWidget(self.loader_output)
        
        # Export buttons
        export_layout = QHBoxLayout()
        
        save_btn = QPushButton("💾 Save Loader")
        save_btn.clicked.connect(self.save_loader)
        export_layout.addWidget(save_btn)
        
        copy_loader_btn = QPushButton("📋 Copy")
        copy_loader_btn.clicked.connect(self.copy_loader)
        export_layout.addWidget(copy_loader_btn)
        
        export_layout.addStretch()
        output_layout.addLayout(export_layout)
        
        layout.addWidget(output_group)
        
        return widget
    
    def create_syscall_tab(self) -> QWidget:
        """Create direct syscall tab"""
        widget = QWidget()
        layout = QVBoxLayout(widget)
        
        # Syscall table
        syscall_group = QGroupBox("Windows Syscall Table")
        syscall_layout = QVBoxLayout(syscall_group)
        
        self.syscall_table = QTableWidget()
        self.syscall_table.setColumnCount(4)
        self.syscall_table.setHorizontalHeaderLabels([
            "Function", "Syscall Number", "Version", "Generate"
        ])
        self.syscall_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        
        # Populate syscalls
        for name, entry in self.evasion.syscall_table.items():
            row = self.syscall_table.rowCount()
            self.syscall_table.insertRow(row)
            self.syscall_table.setItem(row, 0, QTableWidgetItem(name))
            self.syscall_table.setItem(row, 1, QTableWidgetItem(f"0x{entry.number:02X}"))
            self.syscall_table.setItem(row, 2, QTableWidgetItem(entry.version))
            
            gen_btn = QPushButton("⚡")
            gen_btn.clicked.connect(lambda checked, n=name: self.generate_syscall(n))
            self.syscall_table.setCellWidget(row, 3, gen_btn)
        
        syscall_layout.addWidget(self.syscall_table)
        
        layout.addWidget(syscall_group)
        
        # Syscall stub output
        stub_group = QGroupBox("Generated Syscall Stub")
        stub_layout = QVBoxLayout(stub_group)
        
        format_layout = QHBoxLayout()
        format_layout.addWidget(QLabel("Architecture:"))
        self.syscall_arch = QComboBox()
        self.syscall_arch.addItems(["x64", "x86"])
        format_layout.addWidget(self.syscall_arch)
        format_layout.addStretch()
        stub_layout.addLayout(format_layout)
        
        self.syscall_output = QPlainTextEdit()
        self.syscall_output.setReadOnly(True)
        self.syscall_output.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #00ccff;
            }
        """)
        stub_layout.addWidget(self.syscall_output)
        
        # Assembly view
        self.syscall_asm = QPlainTextEdit()
        self.syscall_asm.setReadOnly(True)
        self.syscall_asm.setMaximumHeight(150)
        self.syscall_asm.setStyleSheet("""
            QPlainTextEdit {
                font-family: 'Consolas', monospace;
                background: #0d0d1a;
                color: #ff00ff;
            }
        """)
        stub_layout.addWidget(self.syscall_asm)
        
        layout.addWidget(stub_group)
        
        return widget
    
    # ========== Event Handlers ==========
    
    def detect_edr(self):
        """Detect installed EDRs"""
        self.status_bar.setText("🔍 Detecting EDR products...")
        
        worker = EDRWorker(self.evasion.detect_edr)
        worker.result_ready.connect(self.on_edr_detected)
        worker.error.connect(lambda e: self.status_bar.setText(f"❌ Error: {e}"))
        worker.start()
        self.workers.append(worker)
    
    def on_edr_detected(self, edrs: list):
        """Handle EDR detection results"""
        self.edr_table.setRowCount(0)
        self.recommendations_list.clear()
        
        if not edrs:
            self.status_bar.setText("✅ No EDR products detected")
            return
        
        all_capabilities = set()
        all_bypasses = set()
        
        for edr in edrs:
            row = self.edr_table.rowCount()
            self.edr_table.insertRow(row)
            
            self.edr_table.setItem(row, 0, QTableWidgetItem(edr.product.value.replace("_", " ").title()))
            self.edr_table.setItem(row, 1, QTableWidgetItem(", ".join(edr.processes)))
            self.edr_table.setItem(row, 2, QTableWidgetItem(", ".join(edr.drivers)))
            self.edr_table.setItem(row, 3, QTableWidgetItem(", ".join(edr.services)))
            self.edr_table.setItem(row, 4, QTableWidgetItem(str(len(edr.bypass_techniques))))
            
            all_capabilities.update(edr.detection_capabilities)
            all_bypasses.update(edr.bypass_techniques)
        
        # Update capability cards
        cap_status = {
            "hooks": DetectionVector.USERLAND_HOOKS in all_capabilities,
            "kernel": DetectionVector.KERNEL_CALLBACKS in all_capabilities,
            "etw": DetectionVector.ETW_TELEMETRY in all_capabilities,
            "memory": DetectionVector.MEMORY_SCANNING in all_capabilities,
            "behavior": DetectionVector.BEHAVIOR_ANALYSIS in all_capabilities
        }
        
        for key, detected in cap_status.items():
            if key in self.capability_cards:
                self.capability_cards[key].setText("⚠️" if detected else "✅")
        
        # Update recommendations
        for bypass in all_bypasses:
            item = QListWidgetItem(f"✓ {bypass.value.replace('_', ' ').title()}")
            item.setForeground(QColor("#00ff88"))
            self.recommendations_list.addItem(item)
        
        self.status_bar.setText(f"⚠️ Detected {len(edrs)} EDR product(s)")
    
    def show_edr_details(self, item):
        """Show EDR details"""
        row = item.row()
        product_name = self.edr_table.item(row, 0).text()
        
        for edr in self.evasion.detected_edrs:
            if edr.product.value.replace("_", " ").title() == product_name:
                details = f"""
EDR Product: {product_name}

Processes: {', '.join(edr.processes) or 'None detected'}
Drivers: {', '.join(edr.drivers) or 'None detected'}
Services: {', '.join(edr.services) or 'None detected'}

Detection Capabilities:
{chr(10).join('  • ' + c.value.replace('_', ' ').title() for c in edr.detection_capabilities)}

Recommended Bypasses:
{chr(10).join('  ✓ ' + b.value.replace('_', ' ').title() for b in edr.bypass_techniques)}
"""
                QMessageBox.information(self, "EDR Details", details)
                break
    
    def detect_hooks(self):
        """Detect API hooks"""
        module = self.target_module.currentText()
        self.status_bar.setText(f"🪝 Detecting hooks in {module}...")
        
        worker = EDRWorker(self.evasion.detect_hooks, module)
        worker.result_ready.connect(self.on_hooks_detected)
        worker.error.connect(lambda e: self.status_bar.setText(f"❌ Error: {e}"))
        worker.start()
        self.workers.append(worker)
    
    def on_hooks_detected(self, hooks: list):
        """Handle hook detection results"""
        self.hooks_table.setRowCount(0)
        
        for hook in hooks:
            row = self.hooks_table.rowCount()
            self.hooks_table.insertRow(row)
            
            self.hooks_table.setItem(row, 0, QTableWidgetItem(hook.function_name))
            self.hooks_table.setItem(row, 1, QTableWidgetItem(hook.module))
            self.hooks_table.setItem(row, 2, QTableWidgetItem(hook.hook_type))
            
            edr_item = QTableWidgetItem("⚠️ Yes" if hook.is_edr_hook else "No")
            if hook.is_edr_hook:
                edr_item.setForeground(QColor("#ff6600"))
            self.hooks_table.setItem(row, 3, edr_item)
            
            self.hooks_table.setItem(row, 4, QTableWidgetItem(
                hook.original_bytes.hex() if hook.original_bytes else "N/A"
            ))
        
        self.status_bar.setText(f"🪝 Detected {len(hooks)} potential hooks")
    
    def generate_unhook_code(self):
        """Generate unhooking code"""
        current = self.hooks_table.currentItem()
        if not current:
            # Generate for all hooked functions
            code = ""
            for hook in self.evasion.detected_hooks:
                code += self.evasion.generate_unhooking_code(hook.function_name)
                code += "\n\n"
        else:
            row = current.row()
            func_name = self.hooks_table.item(row, 0).text()
            code = self.evasion.generate_unhooking_code(func_name)
        
        self.unhook_code.setPlainText(code)
        self.status_bar.setText("🔓 Unhooking code generated")
    
    def show_technique(self, item):
        """Show technique details"""
        tech = item.data(Qt.ItemDataRole.UserRole)
        
        descriptions = {
            EvasionTechnique.DIRECT_SYSCALL: """
Direct syscalls bypass userland hooks by directly invoking the kernel
syscall instruction instead of using hooked ntdll.dll functions.
This evades most EDR userland hooking.
            """,
            EvasionTechnique.UNHOOKING: """
Unhooking restores the original function bytes by reading a clean
copy of the DLL from disk and overwriting the hooked bytes in memory.
            """,
            EvasionTechnique.ETW_PATCHING: """
ETW (Event Tracing for Windows) patching disables telemetry by
patching the EtwEventWrite function to return immediately without
logging events.
            """,
            EvasionTechnique.AMSI_BYPASS: """
AMSI bypass disables script scanning by patching AmsiScanBuffer
to return invalid arguments, causing scans to fail gracefully.
            """,
            EvasionTechnique.PPID_SPOOFING: """
PPID spoofing creates processes with a fake parent process ID,
making malicious processes appear to be spawned by legitimate
system processes like explorer.exe.
            """,
            EvasionTechnique.SLEEP_OBFUSCATION: """
Sleep obfuscation encrypts the payload in memory during sleep
periods and changes memory permissions to evade memory scanning.
            """,
            EvasionTechnique.STACK_SPOOFING: """
Stack spoofing manipulates call stacks to hide the true origin
of API calls, making them appear to come from legitimate code.
            """,
            EvasionTechnique.MEMORY_ENCRYPTION: """
Memory encryption XOR encrypts payloads in memory with a random
key, only decrypting when execution is needed.
            """
        }
        
        desc = descriptions.get(tech, f"Description for {tech.value} not available.")
        self.technique_desc.setText(desc.strip())
    
    def generate_technique_code(self):
        """Generate code for selected technique"""
        current = self.techniques_list.currentItem()
        if not current:
            QMessageBox.warning(self, "Error", "Select a technique")
            return
        
        tech = current.data(Qt.ItemDataRole.UserRole)
        
        code_generators = {
            EvasionTechnique.ETW_PATCHING: self.evasion.generate_etw_bypass,
            EvasionTechnique.AMSI_BYPASS: self.evasion.generate_amsi_bypass,
            EvasionTechnique.PPID_SPOOFING: self.evasion.generate_ppid_spoofing,
            EvasionTechnique.SLEEP_OBFUSCATION: self.evasion.generate_sleep_obfuscation,
            EvasionTechnique.STACK_SPOOFING: self.evasion.generate_stack_spoofing,
        }
        
        if tech in code_generators:
            code = code_generators[tech]()
        else:
            code = f"# Code generation for {tech.value} not yet implemented"
        
        self.technique_code.setPlainText(code)
        self.status_bar.setText(f"⚡ Generated {tech.value} code")
    
    def copy_technique_code(self):
        """Copy technique code to clipboard"""
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.technique_code.toPlainText())
        self.status_bar.setText("📋 Code copied to clipboard")
    
    def browse_payload(self):
        """Browse for payload file"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Select Payload", "",
            "Binary Files (*.bin *.raw);;All Files (*)"
        )
        if filepath:
            self.payload_path.setText(filepath)
            with open(filepath, 'rb') as f:
                self.current_payload = f.read()
    
    def generate_loader(self):
        """Generate evasive loader"""
        # Get payload
        payload_input = self.payload_path.text().strip()
        
        if os.path.exists(payload_input):
            with open(payload_input, 'rb') as f:
                payload = f.read()
        elif payload_input:
            try:
                payload = bytes.fromhex(payload_input.replace("\\x", "").replace(" ", ""))
            except ValueError:
                QMessageBox.warning(self, "Error", "Invalid payload")
                return
        else:
            # Use sample payload
            payload = b"\x90\x90\x90\x90\xcc"  # NOPs + INT3
        
        # Get selected techniques
        techniques = [
            tech for tech, cb in self.technique_checkboxes.items()
            if cb.isChecked()
        ]
        
        if not techniques:
            QMessageBox.warning(self, "Error", "Select at least one technique")
            return
        
        # Generate loader
        format_map = {
            "Python": "python",
            "PowerShell": "powershell",
            "C#": "csharp",
            "C/C++": "c"
        }
        output_format = format_map.get(self.loader_format.currentText(), "python")
        
        loader = self.evasion.generate_loader(payload, techniques, output_format)
        wrapped = self.evasion.wrap_payload(payload, techniques)
        
        self.loader_output.setPlainText(loader)
        self.success_rate.setValue(int(wrapped.success_rate * 100))
        
        self.status_bar.setText(f"📦 Loader generated - {len(techniques)} techniques applied")
    
    def save_loader(self):
        """Save generated loader"""
        loader = self.loader_output.toPlainText()
        if not loader:
            QMessageBox.warning(self, "Error", "Generate a loader first")
            return
        
        extensions = {
            "Python": ("Python Files (*.py)", ".py"),
            "PowerShell": ("PowerShell Files (*.ps1)", ".ps1"),
            "C#": ("C# Files (*.cs)", ".cs"),
            "C/C++": ("C/C++ Files (*.c *.cpp)", ".c")
        }
        
        fmt = self.loader_format.currentText()
        filter_str, ext = extensions.get(fmt, ("All Files (*)", ""))
        
        filepath, _ = QFileDialog.getSaveFileName(
            self, "Save Loader", f"loader{ext}", filter_str
        )
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(loader)
            self.status_bar.setText(f"💾 Saved to {filepath}")
    
    def copy_loader(self):
        """Copy loader to clipboard"""
        from PyQt6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText(self.loader_output.toPlainText())
        self.status_bar.setText("📋 Loader copied to clipboard")
    
    def generate_syscall(self, syscall_name: str):
        """Generate syscall stub"""
        arch = self.syscall_arch.currentText()
        stub = self.evasion.generate_direct_syscall(syscall_name, arch)
        
        if not stub:
            self.syscall_output.setPlainText(f"Syscall {syscall_name} not found")
            return
        
        # Format as Python bytes
        python_output = f"# Direct syscall stub for {syscall_name}\n"
        python_output += f"# Architecture: {arch}\n"
        python_output += f"# Syscall number: 0x{self.evasion.syscall_table[syscall_name].number:02X}\n\n"
        python_output += f"stub = {repr(stub)}\n"
        python_output += f"\n# Length: {len(stub)} bytes"
        
        self.syscall_output.setPlainText(python_output)
        
        # Generate assembly view
        if arch == "x64":
            asm = f"""; {syscall_name} direct syscall stub (x64)
mov r10, rcx      ; 4C 8B D1
mov eax, {self.evasion.syscall_table[syscall_name].number:#x}      ; B8 XX XX XX XX
syscall           ; 0F 05
ret               ; C3
"""
        else:
            asm = f"; {syscall_name} syscall stub (x86) - requires WoW64"
        
        self.syscall_asm.setPlainText(asm)
        self.status_bar.setText(f"⚡ Generated syscall stub for {syscall_name}")
