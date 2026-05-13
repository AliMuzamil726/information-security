"""
PASSWORD STRENGTH CHECKER
================================================================================
A comprehensive information security application for evaluating password strength
based on modern security standards.

Author: Information Security Project Team
Version: 1.0
Date: 2024
================================================================================
"""

import sys
import re
import math
import json
from datetime import datetime
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QProgressBar, QTextEdit, QGroupBox,
    QCheckBox, QSpinBox, QMessageBox, QComboBox, QTableWidget, QTableWidgetItem
)
from PyQt5.QtCore import Qt, QTimer, QPropertyAnimation, QEasingCurve, QRect, pyqtSignal
from PyQt5.QtGui import QFont, QColor, QIcon, QPixmap
from PyQt5.QtCore import QSize, QPoint


# ============================================================================
# CORE LOGIC MODULE: Password Strength Analysis Engine
# ============================================================================

class PasswordAnalyzer:
    """
    Core module for password strength analysis.
    Implements comprehensive password evaluation based on NIST standards.
    """
    
    # Common passwords database (simplified for this project)
    COMMON_PASSWORDS = {
        'password', '123456', 'password123', 'admin', 'letmein', 'welcome',
        'monkey', 'dragon', 'master', 'sunshine', 'princess', 'qwerty',
        'abc123', 'password1', '123123', 'welcome1'
    }
    
    # Common breached passwords (dummy dataset)
    BREACHED_PASSWORDS = {
        '123456', 'password', '12345678', 'qwerty', '123456789',
        'letmein', 'welcome', 'monkey', '1234567', 'dragon'
    }
    
    def __init__(self):
        self.password = ""
        self.analysis_result = {}
    
    def analyze(self, password):
        """
        Main analysis function - orchestrates all checks.
        
        Args:
            password (str): Password to analyze
            
        Returns:
            dict: Comprehensive analysis results
        """
        self.password = password
        
        # Initialize result dictionary
        self.analysis_result = {
            'password': password,
            'length_score': 0,
            'character_variety_score': 0,
            'entropy_score': 0,
            'pattern_score': 0,
            'total_score': 0,
            'strength_level': 'Weak',
            'entropy_value': 0.0,
            'time_to_crack': 'Less than a second',
            'feedback': [],
            'strengths': [],
            'weaknesses': [],
            'is_common': False,
            'is_breached': False,
            'recommendations': []
        }
        
        # Perform all checks
        self._check_length()
        self._check_character_variety()
        self._check_entropy()
        self._check_patterns()
        self._check_common_passwords()
        self._check_breached_passwords()
        self._calculate_total_score()
        self._generate_feedback()
        self._estimate_crack_time()
        
        return self.analysis_result
    
    def _check_length(self):
        """Check password length and assign score."""
        length = len(self.password)
        
        if length == 0:
            self.analysis_result['length_score'] = 0
            self.analysis_result['feedback'].append("Password cannot be empty")
        elif length < 6:
            self.analysis_result['length_score'] = 10
            self.analysis_result['weaknesses'].append(f"Too short ({length} characters). Minimum 8 recommended.")
        elif length < 8:
            self.analysis_result['length_score'] = 20
            self.analysis_result['weaknesses'].append(f"Short ({length} characters). Aim for 12+ characters.")
        elif length < 12:
            self.analysis_result['length_score'] = 40
            self.analysis_result['strengths'].append(f"Good length ({length} characters)")
        elif length < 16:
            self.analysis_result['length_score'] = 60
            self.analysis_result['strengths'].append(f"Excellent length ({length} characters)")
        else:
            self.analysis_result['length_score'] = 80
            self.analysis_result['strengths'].append(f"Outstanding length ({length} characters)")
    
    def _check_character_variety(self):
        """Check character variety and assign score."""
        score = 0
        variety_count = 0
        
        has_lowercase = bool(re.search(r'[a-z]', self.password))
        has_uppercase = bool(re.search(r'[A-Z]', self.password))
        has_digits = bool(re.search(r'\d', self.password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', self.password))
        
        if has_lowercase:
            score += 15
            variety_count += 1
            self.analysis_result['strengths'].append("Contains lowercase letters")
        else:
            self.analysis_result['weaknesses'].append("Missing lowercase letters")
        
        if has_uppercase:
            score += 20
            variety_count += 1
            self.analysis_result['strengths'].append("Contains uppercase letters")
        else:
            self.analysis_result['weaknesses'].append("Missing uppercase letters")
        
        if has_digits:
            score += 15
            variety_count += 1
            self.analysis_result['strengths'].append("Contains numbers")
        else:
            self.analysis_result['weaknesses'].append("Missing numbers")
        
        if has_special:
            score += 30
            variety_count += 1
            self.analysis_result['strengths'].append("Contains special characters")
        else:
            self.analysis_result['weaknesses'].append("Missing special characters")
        
        self.analysis_result['character_variety_score'] = score
        self.analysis_result['variety_count'] = variety_count
    
    def _check_entropy(self):
        """
        Calculate password entropy.
        
        Entropy formula: E = log2(R^L)
        Where: R = character space, L = password length
        """
        if len(self.password) == 0:
            self.analysis_result['entropy_value'] = 0.0
            self.analysis_result['entropy_score'] = 0
            return
        
        # Determine character space
        character_space = 0
        if re.search(r'[a-z]', self.password):
            character_space += 26
        if re.search(r'[A-Z]', self.password):
            character_space += 26
        if re.search(r'\d', self.password):
            character_space += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', self.password):
            character_space += 32
        
        # Calculate entropy
        entropy = math.log2(character_space ** len(self.password)) if character_space > 0 else 0
        self.analysis_result['entropy_value'] = round(entropy, 2)
        
        # Score based on entropy
        if entropy < 30:
            self.analysis_result['entropy_score'] = 20
        elif entropy < 50:
            self.analysis_result['entropy_score'] = 40
        elif entropy < 80:
            self.analysis_result['entropy_score'] = 60
        elif entropy < 120:
            self.analysis_result['entropy_score'] = 80
        else:
            self.analysis_result['entropy_score'] = 100
        
        self.analysis_result['feedback'].append(f"Entropy: {entropy:.2f} bits")
    
    def _check_patterns(self):
        """Check for common patterns and assign penalty."""
        score = 100
        
        # Check for sequential characters
        if re.search(r'(012|123|234|345|456|567|678|789|890|abc|bcd|cde|def)', self.password.lower()):
            score -= 20
            self.analysis_result['weaknesses'].append("Contains sequential characters")
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', self.password):
            score -= 15
            self.analysis_result['weaknesses'].append("Contains repeated characters")
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdfgh', 'zxcvbn', '12345', 'qazwsx']
        for pattern in keyboard_patterns:
            if pattern in self.password.lower():
                score -= 20
                self.analysis_result['weaknesses'].append("Contains keyboard pattern")
                break
        
        self.analysis_result['pattern_score'] = max(0, score)
    
    def _check_common_passwords(self):
        """Check if password is in common passwords list."""
        if self.password.lower() in self.COMMON_PASSWORDS:
            self.analysis_result['is_common'] = True
            self.analysis_result['weaknesses'].append("This is a commonly used password")
    
    def _check_breached_passwords(self):
        """Check if password is in breached passwords database."""
        if self.password in self.BREACHED_PASSWORDS:
            self.analysis_result['is_breached'] = True
            self.analysis_result['weaknesses'].append("This password has been found in data breaches")
    
    def _calculate_total_score(self):
        """Calculate total password strength score."""
        # Weighted scoring formula
        weights = {
            'length': 0.25,
            'variety': 0.25,
            'entropy': 0.30,
            'pattern': 0.20
        }
        
        total = (
            self.analysis_result['length_score'] * weights['length'] +
            self.analysis_result['character_variety_score'] * weights['variety'] +
            self.analysis_result['entropy_score'] * weights['entropy'] +
            self.analysis_result['pattern_score'] * weights['pattern']
        )
        
        # Apply penalties
        if self.analysis_result['is_common']:
            total -= 30
        if self.analysis_result['is_breached']:
            total -= 50
        
        self.analysis_result['total_score'] = max(0, min(100, total))
        
        # Determine strength level
        if self.analysis_result['total_score'] >= 80:
            self.analysis_result['strength_level'] = 'Very Strong'
        elif self.analysis_result['total_score'] >= 60:
            self.analysis_result['strength_level'] = 'Strong'
        elif self.analysis_result['total_score'] >= 40:
            self.analysis_result['strength_level'] = 'Moderate'
        else:
            self.analysis_result['strength_level'] = 'Weak'
    
    def _generate_feedback(self):
        """Generate specific recommendations."""
        recommendations = []
        
        if len(self.password) < 12:
            recommendations.append("Use at least 12 characters for better security")
        
        if self.analysis_result['variety_count'] < 4:
            recommendations.append("Include uppercase, lowercase, numbers, and special characters")
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', self.password):
            recommendations.append("Add special characters (!@#$%^&*) for increased security")
        
        if self.analysis_result['is_common']:
            recommendations.append("Avoid common passwords - try something more unique")
        
        if self.analysis_result['is_breached']:
            recommendations.append("CRITICAL: This password has been compromised - change it immediately")
        
        self.analysis_result['recommendations'] = recommendations
    
    def _estimate_crack_time(self):
        """
        Estimate time to crack the password using brute force.
        
        Assumptions:
        - Modern GPU: ~1 billion attempts per second
        - Average case: 50% of keyspace needed
        """
        if self.analysis_result['entropy_value'] == 0:
            self.analysis_result['time_to_crack'] = 'Less than a millisecond'
            return
        
        # Calculate number of possible combinations
        possibilities = 2 ** self.analysis_result['entropy_value']
        
        # Average attempts = possibilities / 2
        avg_attempts = possibilities / 2
        
        # Attempts per second (modern GPU)
        attempts_per_second = 1_000_000_000
        
        seconds = avg_attempts / attempts_per_second
        
        # Convert to human-readable format
        if seconds < 1:
            self.analysis_result['time_to_crack'] = 'Less than a millisecond'
        elif seconds < 60:
            self.analysis_result['time_to_crack'] = f'{seconds:.2f} seconds'
        elif seconds < 3600:
            minutes = seconds / 60
            self.analysis_result['time_to_crack'] = f'{minutes:.2f} minutes'
        elif seconds < 86400:
            hours = seconds / 3600
            self.analysis_result['time_to_crack'] = f'{hours:.2f} hours'
        elif seconds < 31536000:
            days = seconds / 86400
            self.analysis_result['time_to_crack'] = f'{days:.2f} days'
        else:
            years = seconds / 31536000
            self.analysis_result['time_to_crack'] = f'{years:.2f} years'
    
    def generate_password(self, length=16):
        """
        Generate a strong random password.
        
        Args:
            length (int): Desired password length
            
        Returns:
            str: Generated password
        """
        import random
        import string
        
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        all_chars = lowercase + uppercase + digits + special
        
        # Ensure at least one of each character type
        password = [
            random.choice(lowercase),
            random.choice(uppercase),
            random.choice(digits),
            random.choice(special)
        ]
        
        # Fill remaining length with random characters
        for _ in range(length - 4):
            password.append(random.choice(all_chars))
        
        # Shuffle
        random.shuffle(password)
        
        return ''.join(password)


# ============================================================================
# UI MODULE: Main Application Window
# ============================================================================

class PasswordStrengthCheckerUI(QMainWindow):
    """Main application window with modern UI design."""
    
    password_changed = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.analyzer = PasswordAnalyzer()
        self.init_ui()
        self.setup_styles()
        
    def init_ui(self):
        """Initialize user interface."""
        self.setWindowTitle('Password Strength Checker - Information Security Tool')
        self.setGeometry(100, 100, 900, 800)
        self.setMinimumSize(900, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setSpacing(15)
        main_layout.setContentsMargins(20, 20, 20, 20)
        
        # Header
        self._create_header(main_layout)
        
        # Password Input Section
        self._create_password_input_section(main_layout)
        
        # Strength Meter Section
        self._create_strength_meter_section(main_layout)
        
        # Analysis Results Section
        self._create_analysis_section(main_layout)
        
        # Feedback Section
        self._create_feedback_section(main_layout)
        
        # Action Buttons Section
        self._create_buttons_section(main_layout)
        
        # Timer for real-time analysis
        self.analysis_timer = QTimer()
        self.analysis_timer.timeout.connect(self.analyze_password)
        self.password_input.textChanged.connect(self.on_password_changed)
    
    def _create_header(self, layout):
        """Create header section."""
        header_label = QLabel('Password Strength Checker')
        header_font = QFont()
        header_font.setPointSize(24)
        header_font.setBold(True)
        header_label.setFont(header_font)
        header_label.setAlignment(Qt.AlignCenter) # pyright: ignore[reportAttributeAccessIssue]
        
        subtitle = QLabel('Real-time password analysis based on modern security standards')
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)
        subtitle_font.setItalic(True)
        subtitle.setFont(subtitle_font)
        subtitle.setAlignment(Qt.AlignCenter) # pyright: ignore[reportAttributeAccessIssue]
        subtitle.setStyleSheet("color: #666666;")
        
        layout.addWidget(header_label)
        layout.addWidget(subtitle)
    
    def _create_password_input_section(self, layout):
        """Create password input section."""
        group = QGroupBox("Enter Password")
        group_layout = QVBoxLayout()
        
        # Password input
        label = QLabel("Password:")
        label_font = QFont()
        label_font.setPointSize(11)
        label.setFont(label_font)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumHeight(40)
        self.password_input.setFont(QFont('Arial', 11))
        self.password_input.setPlaceholderText('Enter a password to analyze...')
        
        # Show/Hide password toggle
        self.show_password_btn = QPushButton('👁 Show')
        self.show_password_btn.setMaximumWidth(80)
        self.show_password_btn.clicked.connect(self.toggle_password_visibility)
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(self.password_input)
        input_layout.addWidget(self.show_password_btn)
        
        group_layout.addWidget(label)
        group_layout.addLayout(input_layout)
        
        group.setLayout(group_layout)
        layout.addWidget(group)
    
    def _create_strength_meter_section(self, layout):
        """Create strength meter visualization."""
        group = QGroupBox("Strength Meter")
        group_layout = QVBoxLayout()
        
        # Strength label
        self.strength_label = QLabel('Strength: None')
        strength_font = QFont()
        strength_font.setPointSize(12)
        strength_font.setBold(True)
        self.strength_label.setFont(strength_font)
        
        # Progress bar (strength meter)
        self.strength_bar = QProgressBar()
        self.strength_bar.setMinimum(0)
        self.strength_bar.setMaximum(100)
        self.strength_bar.setValue(0)
        self.strength_bar.setMinimumHeight(30)
        
        # Score label
        self.score_label = QLabel('Score: 0/100')
        score_font = QFont()
        score_font.setPointSize(10)
        self.score_label.setFont(score_font)
        
        group_layout.addWidget(self.strength_label)
        group_layout.addWidget(self.strength_bar)
        group_layout.addWidget(self.score_label)
        
        group.setLayout(group_layout)
        layout.addWidget(group)
    
    def _create_analysis_section(self, layout):
        """Create detailed analysis section."""
        group = QGroupBox("Detailed Analysis")
        group_layout = QVBoxLayout()
        
        # Create a table for analysis details
        self.analysis_table = QTableWidget()
        self.analysis_table.setColumnCount(2)
        self.analysis_table.setHorizontalHeaderLabels(['Metric', 'Value'])
        self.analysis_table.horizontalHeader().setStretchLastSection(True)
        self.analysis_table.setMaximumHeight(150)
        
        metrics = [
            ('Password Length', '0'),
            ('Character Variety', '0/4'),
            ('Entropy (bits)', '0.0'),
            ('Time to Crack', 'N/A'),
            ('Common Password', 'No'),
            ('Breached Password', 'No'),
        ]
        
        self.analysis_table.setRowCount(len(metrics))
        for i, (metric, value) in enumerate(metrics):
            self.analysis_table.setItem(i, 0, QTableWidgetItem(metric))
            self.analysis_table.setItem(i, 1, QTableWidgetItem(value))
        
        group_layout.addWidget(self.analysis_table)
        group.setLayout(group_layout)
        layout.addWidget(group)
    
    def _create_feedback_section(self, layout):
        """Create feedback and recommendations section."""
        group = QGroupBox("Strengths, Weaknesses & Recommendations")
        group_layout = QVBoxLayout()
        
        self.feedback_text = QTextEdit()
        self.feedback_text.setReadOnly(True)
        self.feedback_text.setMinimumHeight(120)
        self.feedback_text.setFont(QFont('Arial', 10))
        
        group_layout.addWidget(self.feedback_text)
        group.setLayout(group_layout)
        layout.addWidget(group)
    
    def _create_buttons_section(self, layout):
        """Create action buttons."""
        buttons_layout = QHBoxLayout()
        
        # Generate password button
        self.generate_btn = QPushButton('🔐 Generate Strong Password')
        self.generate_btn.setMinimumHeight(40)
        self.generate_btn.clicked.connect(self.generate_password)
        self.generate_btn.setFont(QFont('Arial', 10))
        
        # Copy button
        self.copy_btn = QPushButton('📋 Copy Password')
        self.copy_btn.setMinimumHeight(40)
        self.copy_btn.clicked.connect(self.copy_password)
        self.copy_btn.setFont(QFont('Arial', 10))
        self.copy_btn.setEnabled(False)
        
        # Clear button
        self.clear_btn = QPushButton('🗑 Clear')
        self.clear_btn.setMinimumHeight(40)
        self.clear_btn.clicked.connect(self.clear_input)
        self.clear_btn.setFont(QFont('Arial', 10))
        
        buttons_layout.addWidget(self.generate_btn)
        buttons_layout.addWidget(self.copy_btn)
        buttons_layout.addWidget(self.clear_btn)
        
        layout.addLayout(buttons_layout)
    
    def setup_styles(self):
        """Setup application styles and themes."""
        style = """
        QGroupBox {
            border: 1px solid #CCCCCC;
            border-radius: 5px;
            margin-top: 8px;
            padding-top: 8px;
            font-weight: bold;
        }
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 3px 0 3px;
        }
        QLineEdit {
            border: 2px solid #CCCCCC;
            border-radius: 5px;
            padding: 8px;
            background-color: white;
        }
        QLineEdit:focus {
            border: 2px solid #2E75B6;
            background-color: #F0F8FF;
        }
        QPushButton {
            background-color: #2E75B6;
            color: white;
            border: none;
            border-radius: 5px;
            padding: 8px;
            font-weight: bold;
        }
        QPushButton:hover {
            background-color: #1E5A96;
        }
        QPushButton:pressed {
            background-color: #0F3D6E;
        }
        QProgressBar {
            border: 2px solid #CCCCCC;
            border-radius: 5px;
            background-color: #F0F0F0;
            text-align: center;
        }
        QProgressBar::chunk {
            background-color: #2ECC71;
            border-radius: 3px;
        }
        QTextEdit {
            border: 2px solid #CCCCCC;
            border-radius: 5px;
            background-color: white;
        }
        QTableWidget {
            border: 1px solid #CCCCCC;
            border-radius: 5px;
            gridline-color: #EEEEEE;
        }
        QTableWidget::item {
            padding: 5px;
        }
        QHeaderView::section {
            background-color: #E8E8E8;
            padding: 5px;
            border: 1px solid #CCCCCC;
            font-weight: bold;
        }
        """
        self.setStyleSheet(style)
    
    # ========================================================================
    # SLOTS AND EVENT HANDLERS
    # ========================================================================
    
    def on_password_changed(self):
        """Handle password input changes."""
        self.analysis_timer.stop()
        self.analysis_timer.start(500)  # Analyze after 500ms of inactivity
        self.copy_btn.setEnabled(len(self.password_input.text()) > 0)
    
    def analyze_password(self):
        """Analyze the entered password."""
        password = self.password_input.text()
        
        if not password:
            self.reset_display()
            return
        
        # Perform analysis
        result = self.analyzer.analyze(password)
        
        # Update UI
        self.update_strength_display(result)
        self.update_analysis_table(result)
        self.update_feedback(result)
    
    def update_strength_display(self, result):
        """Update strength meter and label."""
        score = int(result['total_score'])
        strength = result['strength_level']
        
        # Update progress bar
        self.strength_bar.setValue(score)
        
        # Update labels
        self.strength_label.setText(f"Strength: {strength}")
        self.score_label.setText(f"Score: {score}/100")
        
        # Update colors based on strength
        color_map = {
            'Weak': '#E74C3C',
            'Moderate': '#F39C12',
            'Strong': '#27AE60',
            'Very Strong': '#16A085'
        }
        
        color = color_map.get(strength, '#95A5A6')
        self.strength_label.setStyleSheet(f"color: {color};")
        
        # Update progress bar chunk color
        stylesheet = f"""
        QProgressBar::chunk {{
            background-color: {color};
            border-radius: 3px;
        }}
        """
        self.strength_bar.setStyleSheet(stylesheet)
    
    def update_analysis_table(self, result):
        """Update analysis details table."""
        updates = [
            (0, f"{len(result['password'])}"),
            (1, f"{result['variety_count']}/4"),
            (2, f"{result['entropy_value']}"),
            (3, result['time_to_crack']),
            (4, "Yes" if result['is_common'] else "No"),
            (5, "Yes" if result['is_breached'] else "No"),
        ]
        
        for row, value in updates:
            item = QTableWidgetItem(value)
            self.analysis_table.setItem(row, 1, item)
    
    def update_feedback(self, result):
        """Update feedback section."""
        feedback = []
        
        # Strengths
        if result['strengths']:
            feedback.append("✓ STRENGTHS:")
            for strength in result['strengths']:
                feedback.append(f"  • {strength}")
            feedback.append("")
        
        # Weaknesses
        if result['weaknesses']:
            feedback.append("✗ WEAKNESSES:")
            for weakness in result['weaknesses']:
                feedback.append(f"  • {weakness}")
            feedback.append("")
        
        # Recommendations
        if result['recommendations']:
            feedback.append("💡 RECOMMENDATIONS:")
            for rec in result['recommendations']:
                feedback.append(f"  • {rec}")
        
        self.feedback_text.setText('\n'.join(feedback))
    
    def reset_display(self):
        """Reset all displays to initial state."""
        self.strength_label.setText('Strength: None')
        self.strength_bar.setValue(0)
        self.score_label.setText('Score: 0/100')
        
        # Reset table
        for i in range(self.analysis_table.rowCount()):
            self.analysis_table.setItem(i, 1, QTableWidgetItem('N/A' if i != 4 and i != 5 else 'No'))
        
        self.feedback_text.setText('Enter a password to see analysis...')
    
    def toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.password_input.echoMode() == QLineEdit.Password:
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.show_password_btn.setText('👁‍🗨 Hide')
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.show_password_btn.setText('👁 Show')
    
    def generate_password(self):
        """Generate and insert a strong password."""
        generated = self.analyzer.generate_password(16)
        self.password_input.setText(generated)
    
    def copy_password(self):
        """Copy password to clipboard."""
        clipboard = QApplication.clipboard()
        clipboard.setText(self.password_input.text())
        QMessageBox.information(self, 'Success', 'Password copied to clipboard!')
    
    def clear_input(self):
        """Clear password input."""
        self.password_input.clear()
        self.reset_display()


# ============================================================================
# APPLICATION ENTRY POINT
# ============================================================================

def main():
    """Application entry point."""
    app = QApplication(sys.argv)
    window = PasswordStrengthCheckerUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()