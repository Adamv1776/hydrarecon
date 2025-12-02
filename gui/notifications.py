#!/usr/bin/env python3
"""
HydraRecon Real-time Notification System
████████████████████████████████████████████████████████████████████████████████
█  LIVE ALERTS - Desktop Notifications, Sound Alerts, Event Logging            █
████████████████████████████████████████████████████████████████████████████████
"""

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QGraphicsDropShadowEffect, QSystemTrayIcon, QMenu,
    QApplication, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve, pyqtSignal,
    QPoint, QRect, QSize, QSequentialAnimationGroup, QParallelAnimationGroup
)
from PyQt6.QtGui import QFont, QColor, QPainter, QPen, QBrush, QIcon, QPixmap

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Callable
from enum import Enum
import json


class NotificationType(Enum):
    INFO = ("info", "#00d4ff", "ℹ️")
    SUCCESS = ("success", "#00ff9d", "✅")
    WARNING = ("warning", "#ffaa00", "⚠️")
    ERROR = ("error", "#ff0040", "❌")
    CRITICAL = ("critical", "#ff0040", "🚨")
    SCAN_COMPLETE = ("scan_complete", "#00ff9d", "🔍")
    CREDENTIAL_FOUND = ("credential_found", "#ffaa00", "🔑")
    VULNERABILITY_FOUND = ("vulnerability_found", "#ff0040", "🛡️")
    SESSION_OPENED = ("session_opened", "#00ff9d", "💻")
    
    def __init__(self, name: str, color: str, icon: str):
        self.type_name = name
        self.color = color
        self.icon = icon


@dataclass
class Notification:
    """Notification data"""
    id: int
    type: NotificationType
    title: str
    message: str
    timestamp: datetime = field(default_factory=datetime.now)
    read: bool = False
    action_callback: Optional[Callable] = None
    action_label: str = ""
    data: dict = field(default_factory=dict)


class NotificationToast(QFrame):
    """
    Animated toast notification widget
    """
    
    clicked = pyqtSignal(object)
    closed = pyqtSignal(object)
    
    def __init__(self, notification: Notification, parent=None):
        super().__init__(parent)
        self.notification = notification
        self.setWindowFlags(
            Qt.WindowType.FramelessWindowHint |
            Qt.WindowType.WindowStaysOnTopHint |
            Qt.WindowType.Tool
        )
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        
        self._setup_ui()
        self._setup_animations()
    
    def _setup_ui(self):
        self.setFixedSize(380, 100)
        
        # Main container
        container = QFrame(self)
        container.setGeometry(0, 0, 380, 100)
        container.setStyleSheet(f"""
            QFrame {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #1a2235, stop:1 #151b2d);
                border: 1px solid {self.notification.type.color};
                border-left: 4px solid {self.notification.type.color};
                border-radius: 10px;
            }}
        """)
        
        # Shadow effect
        shadow = QGraphicsDropShadowEffect()
        shadow.setBlurRadius(20)
        shadow.setColor(QColor(0, 0, 0, 100))
        shadow.setOffset(0, 5)
        container.setGraphicsEffect(shadow)
        
        layout = QHBoxLayout(container)
        layout.setContentsMargins(15, 10, 15, 10)
        layout.setSpacing(12)
        
        # Icon
        icon_label = QLabel(self.notification.type.icon)
        icon_label.setStyleSheet("font-size: 28px;")
        layout.addWidget(icon_label)
        
        # Content
        content_layout = QVBoxLayout()
        content_layout.setSpacing(4)
        
        title = QLabel(self.notification.title)
        title.setStyleSheet(f"""
            color: {self.notification.type.color};
            font-weight: bold;
            font-size: 14px;
        """)
        content_layout.addWidget(title)
        
        message = QLabel(self.notification.message)
        message.setStyleSheet("color: #888; font-size: 12px;")
        message.setWordWrap(True)
        content_layout.addWidget(message)
        
        timestamp = QLabel(self.notification.timestamp.strftime("%H:%M:%S"))
        timestamp.setStyleSheet("color: #555; font-size: 10px;")
        content_layout.addWidget(timestamp)
        
        layout.addLayout(content_layout, stretch=1)
        
        # Close button
        close_btn = QPushButton("×")
        close_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #888;
                font-size: 20px;
                border: none;
                padding: 0;
                min-width: 24px;
                min-height: 24px;
            }
            QPushButton:hover {
                color: #ff0040;
            }
        """)
        close_btn.clicked.connect(self._close)
        layout.addWidget(close_btn, alignment=Qt.AlignmentFlag.AlignTop)
    
    def _setup_animations(self):
        """Setup slide-in and fade animations"""
        self.slide_in = QPropertyAnimation(self, b"pos")
        self.slide_in.setDuration(300)
        self.slide_in.setEasingCurve(QEasingCurve.Type.OutCubic)
        
        self.fade_out = QPropertyAnimation(self, b"windowOpacity")
        self.fade_out.setDuration(200)
        self.fade_out.setStartValue(1.0)
        self.fade_out.setEndValue(0.0)
        self.fade_out.finished.connect(self._on_fade_complete)
    
    def show_toast(self, start_pos: QPoint, end_pos: QPoint):
        """Show toast with slide animation"""
        self.slide_in.setStartValue(start_pos)
        self.slide_in.setEndValue(end_pos)
        self.show()
        self.slide_in.start()
        
        # Auto-close after 5 seconds
        QTimer.singleShot(5000, self._close)
    
    def _close(self):
        """Close toast with fade animation"""
        self.fade_out.start()
    
    def _on_fade_complete(self):
        """Handle fade complete"""
        self.closed.emit(self.notification)
        self.close()
        self.deleteLater()
    
    def mousePressEvent(self, event):
        """Handle click"""
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.notification)
            if self.notification.action_callback:
                self.notification.action_callback()
        super().mousePressEvent(event)


class NotificationPanel(QFrame):
    """
    Notification history panel
    """
    
    notification_clicked = pyqtSignal(object)
    clear_all = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.notifications: List[Notification] = []
        self._setup_ui()
    
    def _setup_ui(self):
        self.setStyleSheet("""
            QFrame {
                background: #151b2d;
                border: 1px solid #2a3548;
                border-radius: 10px;
            }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        
        # Header
        header = QFrame()
        header.setStyleSheet("""
            QFrame {
                background: #1a2235;
                border: none;
                border-bottom: 1px solid #2a3548;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
            }
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(15, 12, 15, 12)
        
        title = QLabel("🔔 Notifications")
        title.setStyleSheet("color: #00ff9d; font-weight: bold; font-size: 14px;")
        header_layout.addWidget(title)
        
        self.count_label = QLabel("0")
        self.count_label.setStyleSheet("""
            background: #ff0040;
            color: white;
            font-weight: bold;
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 10px;
        """)
        header_layout.addWidget(self.count_label)
        
        header_layout.addStretch()
        
        clear_btn = QPushButton("Clear All")
        clear_btn.setStyleSheet("""
            QPushButton {
                background: transparent;
                color: #888;
                border: none;
                font-size: 12px;
            }
            QPushButton:hover {
                color: #00ff9d;
            }
        """)
        clear_btn.clicked.connect(self._clear_all)
        header_layout.addWidget(clear_btn)
        
        layout.addWidget(header)
        
        # Scroll area for notifications
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("""
            QScrollArea {
                background: transparent;
                border: none;
            }
            QScrollBar:vertical {
                background: #1a2235;
                width: 8px;
                border-radius: 4px;
            }
            QScrollBar::handle:vertical {
                background: #2a3548;
                border-radius: 4px;
            }
        """)
        
        self.content = QWidget()
        self.content_layout = QVBoxLayout(self.content)
        self.content_layout.setContentsMargins(10, 10, 10, 10)
        self.content_layout.setSpacing(8)
        self.content_layout.addStretch()
        
        scroll.setWidget(self.content)
        layout.addWidget(scroll)
    
    def add_notification(self, notification: Notification):
        """Add a notification to the panel"""
        self.notifications.insert(0, notification)
        self._update_display()
    
    def _update_display(self):
        """Update the notification display"""
        # Clear existing items (except stretch)
        while self.content_layout.count() > 1:
            item = self.content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        
        # Add notification items
        for notif in self.notifications[:50]:  # Limit to 50
            item = self._create_notification_item(notif)
            self.content_layout.insertWidget(self.content_layout.count() - 1, item)
        
        # Update count
        unread = sum(1 for n in self.notifications if not n.read)
        self.count_label.setText(str(unread))
        self.count_label.setVisible(unread > 0)
    
    def _create_notification_item(self, notification: Notification) -> QFrame:
        """Create a notification list item"""
        item = QFrame()
        item.setStyleSheet(f"""
            QFrame {{
                background: {'#1a2235' if notification.read else '#1f2940'};
                border: 1px solid #2a3548;
                border-left: 3px solid {notification.type.color};
                border-radius: 5px;
            }}
            QFrame:hover {{
                background: #252d42;
            }}
        """)
        item.setCursor(Qt.CursorShape.PointingHandCursor)
        
        layout = QHBoxLayout(item)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)
        
        # Icon
        icon = QLabel(notification.type.icon)
        layout.addWidget(icon)
        
        # Content
        content = QVBoxLayout()
        content.setSpacing(2)
        
        title = QLabel(notification.title)
        title.setStyleSheet(f"color: {notification.type.color}; font-weight: bold; font-size: 12px;")
        content.addWidget(title)
        
        message = QLabel(notification.message[:50] + "..." if len(notification.message) > 50 else notification.message)
        message.setStyleSheet("color: #888; font-size: 11px;")
        content.addWidget(message)
        
        time_str = notification.timestamp.strftime("%H:%M")
        time_label = QLabel(time_str)
        time_label.setStyleSheet("color: #555; font-size: 10px;")
        content.addWidget(time_label)
        
        layout.addLayout(content, stretch=1)
        
        return item
    
    def _clear_all(self):
        """Clear all notifications"""
        self.notifications.clear()
        self._update_display()
        self.clear_all.emit()


class NotificationManager:
    """
    Central notification management
    Handles toast display, history, and system tray integration
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._initialized = True
        self.notifications: List[Notification] = []
        self.active_toasts: List[NotificationToast] = []
        self.panel: Optional[NotificationPanel] = None
        self.tray_icon: Optional[QSystemTrayIcon] = None
        self._next_id = 1
        self._toast_offset = 0
        self._max_visible_toasts = 5
        
        # Callbacks
        self.on_notification: Optional[Callable[[Notification], None]] = None
    
    def setup_tray_icon(self, parent: QWidget):
        """Setup system tray icon for notifications"""
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon = QSystemTrayIcon(parent)
            
            # Create icon (simple colored circle)
            pixmap = QPixmap(32, 32)
            pixmap.fill(Qt.GlobalColor.transparent)
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setBrush(QBrush(QColor("#00ff9d")))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(4, 4, 24, 24)
            painter.end()
            
            self.tray_icon.setIcon(QIcon(pixmap))
            self.tray_icon.setToolTip("HydraRecon")
            
            # Context menu
            menu = QMenu()
            menu.addAction("Show App", lambda: parent.show())
            menu.addSeparator()
            menu.addAction("Exit", lambda: QApplication.quit())
            
            self.tray_icon.setContextMenu(menu)
            self.tray_icon.show()
    
    def notify(self, type: NotificationType, title: str, message: str,
              action_callback: Callable = None, action_label: str = "",
              data: dict = None, show_toast: bool = True) -> Notification:
        """
        Create and show a notification
        """
        notification = Notification(
            id=self._next_id,
            type=type,
            title=title,
            message=message,
            action_callback=action_callback,
            action_label=action_label,
            data=data or {}
        )
        self._next_id += 1
        
        self.notifications.insert(0, notification)
        
        # Show toast notification
        if show_toast and len(self.active_toasts) < self._max_visible_toasts:
            self._show_toast(notification)
        
        # Update panel if exists
        if self.panel:
            self.panel.add_notification(notification)
        
        # System tray notification
        if self.tray_icon and self.tray_icon.isVisible():
            self.tray_icon.showMessage(
                title, message,
                QSystemTrayIcon.MessageIcon.Information, 3000
            )
        
        # Callback
        if self.on_notification:
            self.on_notification(notification)
        
        return notification
    
    def _show_toast(self, notification: Notification):
        """Show toast notification"""
        screen = QApplication.primaryScreen()
        if not screen:
            return
        
        screen_rect = screen.availableGeometry()
        
        toast = NotificationToast(notification)
        toast.closed.connect(self._on_toast_closed)
        
        # Calculate position
        y_offset = 20 + (len(self.active_toasts) * 110)
        start_pos = QPoint(screen_rect.right() + 10, screen_rect.top() + y_offset)
        end_pos = QPoint(screen_rect.right() - 400, screen_rect.top() + y_offset)
        
        self.active_toasts.append(toast)
        toast.show_toast(start_pos, end_pos)
    
    def _on_toast_closed(self, notification: Notification):
        """Handle toast closed"""
        for toast in self.active_toasts[:]:
            if toast.notification.id == notification.id:
                self.active_toasts.remove(toast)
                break
        
        # Reposition remaining toasts
        self._reposition_toasts()
    
    def _reposition_toasts(self):
        """Reposition active toasts"""
        screen = QApplication.primaryScreen()
        if not screen:
            return
        
        screen_rect = screen.availableGeometry()
        
        for i, toast in enumerate(self.active_toasts):
            y_offset = 20 + (i * 110)
            toast.move(screen_rect.right() - 400, screen_rect.top() + y_offset)
    
    # Convenience methods
    def info(self, title: str, message: str, **kwargs) -> Notification:
        return self.notify(NotificationType.INFO, title, message, **kwargs)
    
    def success(self, title: str, message: str, **kwargs) -> Notification:
        return self.notify(NotificationType.SUCCESS, title, message, **kwargs)
    
    def warning(self, title: str, message: str, **kwargs) -> Notification:
        return self.notify(NotificationType.WARNING, title, message, **kwargs)
    
    def error(self, title: str, message: str, **kwargs) -> Notification:
        return self.notify(NotificationType.ERROR, title, message, **kwargs)
    
    def critical(self, title: str, message: str, **kwargs) -> Notification:
        return self.notify(NotificationType.CRITICAL, title, message, **kwargs)
    
    def scan_complete(self, title: str, message: str, **kwargs) -> Notification:
        return self.notify(NotificationType.SCAN_COMPLETE, title, message, **kwargs)
    
    def credential_found(self, title: str, message: str, **kwargs) -> Notification:
        return self.notify(NotificationType.CREDENTIAL_FOUND, title, message, **kwargs)
    
    def vulnerability_found(self, title: str, message: str, **kwargs) -> Notification:
        return self.notify(NotificationType.VULNERABILITY_FOUND, title, message, **kwargs)
    
    def session_opened(self, title: str, message: str, **kwargs) -> Notification:
        return self.notify(NotificationType.SESSION_OPENED, title, message, **kwargs)
    
    def get_unread_count(self) -> int:
        """Get count of unread notifications"""
        return sum(1 for n in self.notifications if not n.read)
    
    def mark_all_read(self):
        """Mark all notifications as read"""
        for n in self.notifications:
            n.read = True
        if self.panel:
            self.panel._update_display()
    
    def clear_all(self):
        """Clear all notifications"""
        self.notifications.clear()
        if self.panel:
            self.panel._update_display()


# Global notification manager instance
notifications = NotificationManager()


# Convenience functions
def notify(type: NotificationType, title: str, message: str, **kwargs) -> Notification:
    """Quick notification function"""
    return notifications.notify(type, title, message, **kwargs)


def info(title: str, message: str, **kwargs) -> Notification:
    return notifications.info(title, message, **kwargs)


def success(title: str, message: str, **kwargs) -> Notification:
    return notifications.success(title, message, **kwargs)


def warning(title: str, message: str, **kwargs) -> Notification:
    return notifications.warning(title, message, **kwargs)


def error(title: str, message: str, **kwargs) -> Notification:
    return notifications.error(title, message, **kwargs)
