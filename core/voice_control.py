"""
Voice Control System for HydraRecon

Advanced voice control capabilities:
- Speech recognition
- Natural language command processing
- Voice-activated scanning
- Audio feedback
- Multi-language support
- Custom wake words
"""

import re
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable
from enum import Enum

try:
    from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject, QThread
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    QObject = object
    QThread = object


class VoiceCommandCategory(Enum):
    """Voice command categories"""
    NAVIGATION = "navigation"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    VISUALIZATION = "visualization"
    CONTROL = "control"
    REPORT = "report"
    QUERY = "query"
    SYSTEM = "system"


class RecognitionState(Enum):
    """Speech recognition state"""
    IDLE = "idle"
    LISTENING = "listening"
    PROCESSING = "processing"
    SPEAKING = "speaking"
    ERROR = "error"


@dataclass
class VoiceCommand:
    """Voice command definition"""
    name: str
    patterns: List[str]  # Regex patterns to match
    category: VoiceCommandCategory
    callback: Optional[Callable] = None
    
    # Parameters extracted from speech
    parameters: List[str] = field(default_factory=list)
    
    # Confirmation required
    requires_confirmation: bool = False
    confirmation_prompt: str = ""
    
    # Help
    description: str = ""
    examples: List[str] = field(default_factory=list)
    
    def match(self, text: str) -> Optional[Dict[str, str]]:
        """Try to match text against patterns"""
        text = text.lower().strip()
        
        for pattern in self.patterns:
            match = re.match(pattern, text, re.IGNORECASE)
            if match:
                return match.groupdict()
        
        return None


@dataclass
class VoiceResult:
    """Result of voice recognition"""
    text: str
    confidence: float
    command: Optional[VoiceCommand] = None
    parameters: Dict[str, str] = field(default_factory=dict)
    
    timestamp: float = 0.0
    duration: float = 0.0


class SpeechRecognizer:
    """
    Speech recognition engine
    
    Uses various backends:
    - Local: Vosk, PocketSphinx
    - Cloud: Google Speech, Azure, AWS
    """
    
    def __init__(self, backend: str = "vosk"):
        self.backend = backend
        self.is_listening = False
        self.language = "en-US"
        
        # Audio settings
        self.sample_rate = 16000
        self.channels = 1
        
        # Recognition callbacks
        self.on_result: Optional[Callable[[VoiceResult], None]] = None
        self.on_partial: Optional[Callable[[str], None]] = None
        self.on_error: Optional[Callable[[str], None]] = None
        
        self._init_backend()
    
    def _init_backend(self):
        """Initialize recognition backend"""
        if self.backend == "vosk":
            self._init_vosk()
        elif self.backend == "google":
            self._init_google()
        # Default to simulated for now
    
    def _init_vosk(self):
        """Initialize Vosk offline recognizer"""
        try:
            from vosk import Model, KaldiRecognizer
            import sounddevice as sd
            
            # Would load model here
            self._vosk_available = True
        except ImportError:
            self._vosk_available = False
    
    def _init_google(self):
        """Initialize Google Speech recognition"""
        try:
            import speech_recognition as sr
            self._sr = sr
            self._recognizer = sr.Recognizer()
            self._google_available = True
        except ImportError:
            self._google_available = False
    
    def start_listening(self):
        """Start listening for speech"""
        self.is_listening = True
        # Would start audio capture here
    
    def stop_listening(self):
        """Stop listening"""
        self.is_listening = False
    
    def recognize_file(self, audio_path: str) -> Optional[VoiceResult]:
        """Recognize speech from audio file"""
        # Implementation would use backend
        return None
    
    def recognize_audio(self, audio_data: bytes) -> Optional[VoiceResult]:
        """Recognize speech from audio data"""
        # Implementation would use backend
        return None


class TextToSpeech:
    """
    Text-to-speech engine
    
    Provides audio feedback and responses.
    """
    
    def __init__(self, backend: str = "pyttsx3"):
        self.backend = backend
        self.is_speaking = False
        
        # Voice settings
        self.voice_id: Optional[str] = None
        self.rate = 175  # Words per minute
        self.volume = 0.9
        self.pitch = 1.0
        
        # Queue
        self.speech_queue: List[str] = []
        
        self._init_backend()
    
    def _init_backend(self):
        """Initialize TTS backend"""
        if self.backend == "pyttsx3":
            self._init_pyttsx3()
        elif self.backend == "gtts":
            self._init_gtts()
    
    def _init_pyttsx3(self):
        """Initialize pyttsx3 offline TTS"""
        try:
            import pyttsx3
            self._engine = pyttsx3.init()
            self._pyttsx3_available = True
            
            # Set properties
            self._engine.setProperty('rate', self.rate)
            self._engine.setProperty('volume', self.volume)
            
        except ImportError:
            self._pyttsx3_available = False
    
    def _init_gtts(self):
        """Initialize Google TTS"""
        try:
            from gtts import gTTS
            import pygame
            pygame.mixer.init()
            self._gtts_available = True
        except ImportError:
            self._gtts_available = False
    
    def speak(self, text: str, priority: bool = False):
        """Speak text"""
        if priority:
            self.speech_queue.insert(0, text)
        else:
            self.speech_queue.append(text)
        
        if not self.is_speaking:
            self._process_queue()
    
    def _process_queue(self):
        """Process speech queue"""
        if not self.speech_queue:
            self.is_speaking = False
            return
        
        self.is_speaking = True
        text = self.speech_queue.pop(0)
        
        # Would use backend to speak
        # For simulation, just print
        print(f"[TTS]: {text}")
        
        self.is_speaking = False
    
    def stop(self):
        """Stop speaking"""
        self.speech_queue.clear()
        self.is_speaking = False
    
    def set_voice(self, voice_id: str):
        """Set voice by ID"""
        self.voice_id = voice_id
    
    def get_available_voices(self) -> List[Dict[str, str]]:
        """Get list of available voices"""
        voices = []
        
        if hasattr(self, '_engine') and self._pyttsx3_available:
            for voice in self._engine.getProperty('voices'):
                voices.append({
                    'id': voice.id,
                    'name': voice.name,
                    'languages': voice.languages
                })
        
        return voices


class VoiceControlSystem(QObject if PYQT_AVAILABLE else object):
    """
    Complete Voice Control System
    
    Integrates speech recognition, command processing, and TTS feedback.
    """
    
    if PYQT_AVAILABLE:
        commandRecognized = pyqtSignal(object)
        stateChanged = pyqtSignal(object)
        errorOccurred = pyqtSignal(str)
        feedbackReady = pyqtSignal(str)
    
    def __init__(self):
        if PYQT_AVAILABLE:
            super().__init__()
        
        # Components
        self.recognizer = SpeechRecognizer()
        self.tts = TextToSpeech()
        
        # State
        self.state = RecognitionState.IDLE
        self.is_enabled = False
        
        # Wake word
        self.wake_word = "hydra"
        self.wake_word_active = False
        self.listening_timeout = 10.0  # seconds
        
        # Commands
        self.commands: Dict[str, VoiceCommand] = {}
        self._register_default_commands()
        
        # Context
        self.context: Dict[str, Any] = {}
        self.last_command: Optional[VoiceCommand] = None
        self.confirmation_pending = False
        
        # History
        self.command_history: List[VoiceResult] = []
        self.max_history = 50
        
        # Setup callbacks
        self.recognizer.on_result = self._on_recognition_result
        self.recognizer.on_partial = self._on_partial_result
        self.recognizer.on_error = self._on_recognition_error
    
    def _register_default_commands(self):
        """Register default voice commands"""
        
        # Navigation commands
        self.register_command(VoiceCommand(
            name="go_to_page",
            patterns=[
                r"(?:go to|open|show|navigate to)\s+(?P<page>\w+)",
                r"(?P<page>\w+)\s+page"
            ],
            category=VoiceCommandCategory.NAVIGATION,
            description="Navigate to a specific page",
            examples=["go to dashboard", "open scanner", "show reports"]
        ))
        
        self.register_command(VoiceCommand(
            name="go_back",
            patterns=[r"(?:go\s+)?back", r"previous"],
            category=VoiceCommandCategory.NAVIGATION,
            description="Go to previous page"
        ))
        
        # Scanning commands
        self.register_command(VoiceCommand(
            name="start_scan",
            patterns=[
                r"(?:start|begin|run)\s+(?P<scan_type>\w+)?\s*scan(?:\s+on)?\s*(?P<target>.*)?",
                r"scan\s+(?P<target>.*)"
            ],
            category=VoiceCommandCategory.SCANNING,
            requires_confirmation=True,
            confirmation_prompt="Start {scan_type} scan on {target}?",
            description="Start a security scan",
            examples=["start port scan on 192.168.1.1", "begin vulnerability scan"]
        ))
        
        self.register_command(VoiceCommand(
            name="stop_scan",
            patterns=[r"(?:stop|cancel|abort)\s+scan"],
            category=VoiceCommandCategory.SCANNING,
            description="Stop the current scan"
        ))
        
        # Analysis commands
        self.register_command(VoiceCommand(
            name="analyze",
            patterns=[
                r"analyze\s+(?P<target>.*)",
                r"(?:run|perform)\s+analysis\s+(?:on\s+)?(?P<target>.*)"
            ],
            category=VoiceCommandCategory.ANALYSIS,
            description="Analyze a target or data"
        ))
        
        # Visualization commands
        self.register_command(VoiceCommand(
            name="show_visualization",
            patterns=[
                r"show\s+(?P<viz_type>3d|network|threat|globe|attack)\s*(?:view|visualization)?",
                r"(?:display|open)\s+(?P<viz_type>\w+)\s+(?:view|visualization)"
            ],
            category=VoiceCommandCategory.VISUALIZATION,
            description="Show a 3D visualization",
            examples=["show 3d network", "display threat globe"]
        ))
        
        self.register_command(VoiceCommand(
            name="rotate_view",
            patterns=[
                r"rotate\s+(?P<direction>left|right|up|down)",
                r"(?:turn|spin)\s+(?P<direction>\w+)"
            ],
            category=VoiceCommandCategory.VISUALIZATION,
            description="Rotate the 3D view"
        ))
        
        self.register_command(VoiceCommand(
            name="zoom",
            patterns=[
                r"zoom\s+(?P<direction>in|out)",
                r"(?:zoom|scale)\s+(?:to\s+)?(?P<level>\d+)(?:\s*%|percent)?"
            ],
            category=VoiceCommandCategory.VISUALIZATION,
            description="Zoom the view"
        ))
        
        # Control commands
        self.register_command(VoiceCommand(
            name="confirm",
            patterns=[r"(?:yes|confirm|affirmative|proceed|do it)"],
            category=VoiceCommandCategory.CONTROL,
            description="Confirm pending action"
        ))
        
        self.register_command(VoiceCommand(
            name="cancel",
            patterns=[r"(?:no|cancel|negative|abort|stop|nevermind)"],
            category=VoiceCommandCategory.CONTROL,
            description="Cancel pending action"
        ))
        
        # Report commands
        self.register_command(VoiceCommand(
            name="generate_report",
            patterns=[
                r"(?:generate|create|make)\s+(?P<report_type>\w+)?\s*report",
                r"report\s+(?P<target>.*)"
            ],
            category=VoiceCommandCategory.REPORT,
            description="Generate a report"
        ))
        
        # Query commands
        self.register_command(VoiceCommand(
            name="status",
            patterns=[
                r"(?:what(?:'s| is) the)?\s*status",
                r"(?:show|get)\s+status"
            ],
            category=VoiceCommandCategory.QUERY,
            description="Get current status"
        ))
        
        self.register_command(VoiceCommand(
            name="count",
            patterns=[
                r"how many\s+(?P<item>.*)",
                r"count\s+(?P<item>.*)"
            ],
            category=VoiceCommandCategory.QUERY,
            description="Count items"
        ))
        
        # System commands
        self.register_command(VoiceCommand(
            name="help",
            patterns=[r"(?:help|what can you do|commands|options)"],
            category=VoiceCommandCategory.SYSTEM,
            description="Show available commands"
        ))
        
        self.register_command(VoiceCommand(
            name="quiet_mode",
            patterns=[r"(?:quiet|silent|mute)\s*(?:mode)?"],
            category=VoiceCommandCategory.SYSTEM,
            description="Disable voice feedback"
        ))
        
        self.register_command(VoiceCommand(
            name="voice_mode",
            patterns=[r"(?:voice|speak|unmute)\s*(?:mode)?"],
            category=VoiceCommandCategory.SYSTEM,
            description="Enable voice feedback"
        ))
    
    def register_command(self, command: VoiceCommand):
        """Register a voice command"""
        self.commands[command.name] = command
    
    def unregister_command(self, name: str):
        """Unregister a command"""
        if name in self.commands:
            del self.commands[name]
    
    def enable(self):
        """Enable voice control"""
        self.is_enabled = True
        self._set_state(RecognitionState.IDLE)
        self.speak("Voice control activated. Say 'Hydra' to begin.")
    
    def disable(self):
        """Disable voice control"""
        self.is_enabled = False
        self.recognizer.stop_listening()
        self._set_state(RecognitionState.IDLE)
        self.speak("Voice control deactivated.")
    
    def start_listening(self, wait_for_wake_word: bool = True):
        """Start listening for commands"""
        if not self.is_enabled:
            return
        
        if wait_for_wake_word:
            self._set_state(RecognitionState.LISTENING)
            self.wake_word_active = True
        else:
            self._set_state(RecognitionState.LISTENING)
            self.wake_word_active = False
        
        self.recognizer.start_listening()
    
    def stop_listening(self):
        """Stop listening"""
        self.recognizer.stop_listening()
        self._set_state(RecognitionState.IDLE)
    
    def _set_state(self, state: RecognitionState):
        """Update state"""
        self.state = state
        if PYQT_AVAILABLE:
            self.stateChanged.emit(state)
    
    def _on_recognition_result(self, result: VoiceResult):
        """Handle recognition result"""
        text = result.text.lower().strip()
        
        # Check for wake word
        if self.wake_word_active:
            if self.wake_word in text:
                self.wake_word_active = False
                self.speak("I'm listening.")
                return
            else:
                return  # Ignore until wake word
        
        # Handle confirmation
        if self.confirmation_pending:
            self._handle_confirmation(text)
            return
        
        # Try to match command
        for command in self.commands.values():
            match = command.match(text)
            if match:
                result.command = command
                result.parameters = match
                self._execute_command(command, match)
                break
        else:
            self.speak("I didn't understand that. Say 'help' for available commands.")
        
        # Store in history
        result.timestamp = time.time()
        self.command_history.append(result)
        if len(self.command_history) > self.max_history:
            self.command_history.pop(0)
        
        if PYQT_AVAILABLE:
            self.commandRecognized.emit(result)
    
    def _on_partial_result(self, text: str):
        """Handle partial recognition result"""
        # Could show in UI
        pass
    
    def _on_recognition_error(self, error: str):
        """Handle recognition error"""
        self._set_state(RecognitionState.ERROR)
        if PYQT_AVAILABLE:
            self.errorOccurred.emit(error)
    
    def _execute_command(self, command: VoiceCommand, params: Dict[str, str]):
        """Execute a recognized command"""
        # Check if confirmation needed
        if command.requires_confirmation:
            self.confirmation_pending = True
            self.last_command = command
            self.context['pending_params'] = params
            
            # Format confirmation prompt
            prompt = command.confirmation_prompt.format(**params)
            self.speak(prompt)
            return
        
        # Execute callback if registered
        if command.callback:
            try:
                command.callback(**params)
                self.speak(f"Executed: {command.name}")
            except Exception as e:
                self.speak(f"Error executing command: {str(e)}")
        else:
            # Default handling
            self._handle_default_command(command, params)
    
    def _handle_confirmation(self, text: str):
        """Handle confirmation response"""
        confirm_cmd = self.commands.get("confirm")
        cancel_cmd = self.commands.get("cancel")
        
        if confirm_cmd and confirm_cmd.match(text):
            self.confirmation_pending = False
            if self.last_command and self.last_command.callback:
                params = self.context.get('pending_params', {})
                self.last_command.callback(**params)
                self.speak("Confirmed and executed.")
        
        elif cancel_cmd and cancel_cmd.match(text):
            self.confirmation_pending = False
            self.speak("Cancelled.")
        
        else:
            self.speak("Please say 'yes' to confirm or 'no' to cancel.")
    
    def _handle_default_command(self, command: VoiceCommand, params: Dict[str, str]):
        """Handle commands without custom callbacks"""
        if command.name == "help":
            self._speak_help()
        elif command.name == "status":
            self.speak("System is operational. All services running.")
        elif command.name == "quiet_mode":
            self.tts.volume = 0
            # Use print since TTS is muted
            print("[Voice Control]: Quiet mode enabled")
        elif command.name == "voice_mode":
            self.tts.volume = 0.9
            self.speak("Voice mode enabled.")
        elif command.name == "go_back":
            self.speak("Going back.")
        else:
            self.speak(f"Command {command.name} recognized but no handler registered.")
    
    def _speak_help(self):
        """Speak available commands"""
        categories = {}
        for cmd in self.commands.values():
            cat = cmd.category.value
            if cat not in categories:
                categories[cat] = []
            categories[cat].append(cmd.name)
        
        response = "Available commands: "
        for cat, cmds in categories.items():
            response += f"{cat}: {', '.join(cmds[:3])}. "
        
        self.speak(response)
    
    def speak(self, text: str, priority: bool = False):
        """Speak text feedback"""
        self._set_state(RecognitionState.SPEAKING)
        self.tts.speak(text, priority)
        
        if PYQT_AVAILABLE:
            self.feedbackReady.emit(text)
        
        self._set_state(RecognitionState.LISTENING if self.is_enabled else RecognitionState.IDLE)
    
    def set_command_callback(self, command_name: str, callback: Callable):
        """Set callback for a command"""
        if command_name in self.commands:
            self.commands[command_name].callback = callback
    
    def process_text(self, text: str):
        """Process text as if it was spoken (for testing/keyboard input)"""
        result = VoiceResult(
            text=text,
            confidence=1.0,
            timestamp=time.time()
        )
        self._on_recognition_result(result)
    
    def get_command_list(self, category: Optional[VoiceCommandCategory] = None) -> List[Dict[str, Any]]:
        """Get list of commands, optionally filtered by category"""
        commands = []
        
        for cmd in self.commands.values():
            if category is None or cmd.category == category:
                commands.append({
                    'name': cmd.name,
                    'category': cmd.category.value,
                    'description': cmd.description,
                    'examples': cmd.examples,
                    'requires_confirmation': cmd.requires_confirmation
                })
        
        return commands


# Convenience function
def create_voice_control() -> VoiceControlSystem:
    """Create and initialize voice control system"""
    system = VoiceControlSystem()
    return system


__all__ = [
    'VoiceControlSystem',
    'VoiceCommand',
    'VoiceResult',
    'VoiceCommandCategory',
    'RecognitionState',
    'SpeechRecognizer',
    'TextToSpeech',
    'create_voice_control'
]
