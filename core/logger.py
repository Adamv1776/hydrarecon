#!/usr/bin/env python3
"""
HydraRecon Logging System
Comprehensive logging with file rotation and colored console output.
"""

import logging
import sys
from pathlib import Path
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Optional


class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""
    
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Green
        'WARNING': '\033[33m',    # Yellow
        'ERROR': '\033[31m',      # Red
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # Format the message
        formatted = super().format(record)
        
        return f"{color}{formatted}{reset}"


class ScanLogger:
    """Logger for individual scans with structured output"""
    
    def __init__(self, scan_id: int, scan_type: str, log_dir: Path):
        self.scan_id = scan_id
        self.scan_type = scan_type
        self.log_file = log_dir / f"scan_{scan_id}_{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        
        self.logger = logging.getLogger(f"Scan-{scan_id}")
        self.logger.setLevel(logging.DEBUG)
        
        # File handler for scan-specific log
        file_handler = logging.FileHandler(self.log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        self.logger.addHandler(file_handler)
    
    def log(self, level: str, message: str, **kwargs):
        """Log a message with optional structured data"""
        extra_info = ' | '.join(f'{k}={v}' for k, v in kwargs.items())
        full_message = f"{message} | {extra_info}" if extra_info else message
        getattr(self.logger, level.lower())(full_message)
    
    def debug(self, message: str, **kwargs):
        self.log('debug', message, **kwargs)
    
    def info(self, message: str, **kwargs):
        self.log('info', message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self.log('warning', message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self.log('error', message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        self.log('critical', message, **kwargs)


def setup_logging(log_level: str = "INFO", log_dir: Optional[Path] = None) -> logging.Logger:
    """Setup application-wide logging"""
    
    # Create log directory
    if log_dir is None:
        log_dir = Path.home() / ".hydrarecon" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    
    # Create main logger
    logger = logging.getLogger("HydraRecon")
    logger.setLevel(logging.DEBUG)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    console_handler.setFormatter(ColoredFormatter(
        '%(asctime)s | %(name)-12s | %(levelname)-8s | %(message)s',
        datefmt='%H:%M:%S'
    ))
    logger.addHandler(console_handler)
    
    # File handler with rotation
    log_file = log_dir / f"hydrarecon_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = RotatingFileHandler(
        log_file,
        maxBytes=10*1024*1024,  # 10 MB
        backupCount=5
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(name)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(file_handler)
    
    # Error file handler
    error_file = log_dir / "errors.log"
    error_handler = RotatingFileHandler(
        error_file,
        maxBytes=5*1024*1024,  # 5 MB
        backupCount=3
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(logging.Formatter(
        '%(asctime)s | %(name)s | %(levelname)s | %(funcName)s:%(lineno)d | %(message)s\n%(exc_info)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    ))
    logger.addHandler(error_handler)
    
    logger.info("HydraRecon logging initialized")
    
    return logger


def get_logger(name: str = "HydraRecon") -> logging.Logger:
    """Get a logger instance"""
    return logging.getLogger(name)
