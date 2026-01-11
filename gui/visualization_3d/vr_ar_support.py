"""
VR/AR Support Module for HydraRecon

Provides Virtual Reality and Augmented Reality capabilities:
- OpenXR integration
- Stereoscopic rendering
- Hand tracking
- Gesture recognition
- Spatial UI elements
- Immersive threat visualization
"""

import math
import time
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Callable
from enum import Enum

try:
    from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject
    from PyQt6.QtWidgets import QWidget
    from PyQt6.QtOpenGLWidgets import QOpenGLWidget
    from PyQt6.QtGui import QMatrix4x4, QVector3D, QQuaternion
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    QObject = object

try:
    from OpenGL.GL import *
    from OpenGL.GLU import *
    OPENGL_AVAILABLE = True
except ImportError:
    OPENGL_AVAILABLE = False


class XRMode(Enum):
    """XR rendering mode"""
    DESKTOP = "desktop"
    VR = "vr"
    AR = "ar"
    MIXED = "mixed"


class HandType(Enum):
    """Hand type"""
    LEFT = "left"
    RIGHT = "right"


class GestureType(Enum):
    """Recognized gestures"""
    NONE = "none"
    POINT = "point"
    GRAB = "grab"
    PINCH = "pinch"
    OPEN = "open"
    FIST = "fist"
    THUMBS_UP = "thumbs_up"
    SWIPE_LEFT = "swipe_left"
    SWIPE_RIGHT = "swipe_right"
    SWIPE_UP = "swipe_up"
    SWIPE_DOWN = "swipe_down"
    CIRCLE = "circle"


@dataclass
class XRPose:
    """6DOF pose (position + orientation)"""
    position: Tuple[float, float, float] = (0, 0, 0)
    orientation: Tuple[float, float, float, float] = (0, 0, 0, 1)  # Quaternion
    
    def to_matrix(self) -> np.ndarray:
        """Convert to 4x4 transformation matrix"""
        x, y, z, w = self.orientation
        
        # Rotation matrix from quaternion
        rot = np.array([
            [1 - 2*y*y - 2*z*z, 2*x*y - 2*z*w, 2*x*z + 2*y*w, 0],
            [2*x*y + 2*z*w, 1 - 2*x*x - 2*z*z, 2*y*z - 2*x*w, 0],
            [2*x*z - 2*y*w, 2*y*z + 2*x*w, 1 - 2*x*x - 2*y*y, 0],
            [0, 0, 0, 1]
        ], dtype=np.float32)
        
        # Translation
        rot[0, 3] = self.position[0]
        rot[1, 3] = self.position[1]
        rot[2, 3] = self.position[2]
        
        return rot
    
    def forward(self) -> Tuple[float, float, float]:
        """Get forward direction vector"""
        mat = self.to_matrix()
        return (-mat[2, 0], -mat[2, 1], -mat[2, 2])
    
    def right(self) -> Tuple[float, float, float]:
        """Get right direction vector"""
        mat = self.to_matrix()
        return (mat[0, 0], mat[0, 1], mat[0, 2])
    
    def up(self) -> Tuple[float, float, float]:
        """Get up direction vector"""
        mat = self.to_matrix()
        return (mat[1, 0], mat[1, 1], mat[1, 2])


@dataclass
class HandJoint:
    """Single hand joint"""
    position: Tuple[float, float, float] = (0, 0, 0)
    orientation: Tuple[float, float, float, float] = (0, 0, 0, 1)
    radius: float = 0.01


@dataclass
class HandState:
    """Complete hand tracking state"""
    hand_type: HandType
    is_tracked: bool = False
    
    # Joint positions (standard 26-joint model)
    joints: Dict[str, HandJoint] = field(default_factory=dict)
    
    # Pose
    palm_pose: XRPose = field(default_factory=XRPose)
    aim_pose: XRPose = field(default_factory=XRPose)
    
    # Finger states
    finger_curl: Dict[str, float] = field(default_factory=dict)  # 0-1 per finger
    
    # Gesture
    current_gesture: GestureType = GestureType.NONE
    gesture_confidence: float = 0.0
    
    # Pinch
    pinch_strength: float = 0.0
    grab_strength: float = 0.0


@dataclass
class ControllerState:
    """VR controller state"""
    hand_type: HandType
    is_connected: bool = False
    
    # Pose
    pose: XRPose = field(default_factory=XRPose)
    
    # Buttons
    trigger: float = 0.0
    grip: float = 0.0
    thumbstick: Tuple[float, float] = (0, 0)
    
    buttons: Dict[str, bool] = field(default_factory=dict)
    
    # Haptics
    haptic_amplitude: float = 0.0
    haptic_duration: float = 0.0


@dataclass
class XRView:
    """Single eye view for stereoscopic rendering"""
    eye: str  # "left" or "right"
    pose: XRPose = field(default_factory=XRPose)
    
    fov: Tuple[float, float, float, float] = (-45, 45, -45, 45)  # left, right, down, up
    
    # Render target
    width: int = 1920
    height: int = 1920
    
    # Matrices
    projection_matrix: Optional[np.ndarray] = None
    view_matrix: Optional[np.ndarray] = None
    
    def calculate_projection(self, near: float = 0.1, far: float = 1000.0) -> np.ndarray:
        """Calculate projection matrix from FOV"""
        left = math.tan(math.radians(self.fov[0])) * near
        right = math.tan(math.radians(self.fov[1])) * near
        bottom = math.tan(math.radians(self.fov[2])) * near
        top = math.tan(math.radians(self.fov[3])) * near
        
        projection = np.zeros((4, 4), dtype=np.float32)
        projection[0, 0] = 2 * near / (right - left)
        projection[1, 1] = 2 * near / (top - bottom)
        projection[0, 2] = (right + left) / (right - left)
        projection[1, 2] = (top + bottom) / (top - bottom)
        projection[2, 2] = -(far + near) / (far - near)
        projection[2, 3] = -2 * far * near / (far - near)
        projection[3, 2] = -1
        
        self.projection_matrix = projection
        return projection
    
    def calculate_view(self) -> np.ndarray:
        """Calculate view matrix from pose"""
        pose_matrix = self.pose.to_matrix()
        # Invert for view matrix
        self.view_matrix = np.linalg.inv(pose_matrix)
        return self.view_matrix


class XRSession(QObject if PYQT_AVAILABLE else object):
    """
    XR Session Manager
    
    Manages VR/AR session lifecycle, device tracking, and rendering.
    """
    
    if PYQT_AVAILABLE:
        sessionStarted = pyqtSignal()
        sessionEnded = pyqtSignal()
        poseUpdated = pyqtSignal(object)
        gestureDetected = pyqtSignal(object, object)
        controllerUpdated = pyqtSignal(object)
    
    def __init__(self, mode: XRMode = XRMode.DESKTOP):
        if PYQT_AVAILABLE:
            super().__init__()
        
        self.mode = mode
        self.is_active = False
        
        # Head tracking
        self.head_pose = XRPose()
        
        # Eye views
        self.views: List[XRView] = []
        
        # Hand tracking
        self.left_hand = HandState(HandType.LEFT)
        self.right_hand = HandState(HandType.RIGHT)
        
        # Controllers
        self.left_controller = ControllerState(HandType.LEFT)
        self.right_controller = ControllerState(HandType.RIGHT)
        
        # Tracking space
        self.tracking_origin = XRPose()
        self.play_area_bounds: List[Tuple[float, float]] = []
        
        # Frame timing
        self.target_fps = 90  # Most VR headsets
        self.predicted_display_time = 0.0
        
        # Gesture recognition
        self.gesture_callbacks: Dict[GestureType, List[Callable]] = {}
        
        # Simulation for desktop mode
        self._simulation_timer: Optional[QTimer] = None
        self._mouse_look = False
        self._last_mouse_pos: Optional[Tuple[int, int]] = None
    
    def start_session(self) -> bool:
        """Start XR session"""
        if self.mode == XRMode.DESKTOP:
            self._start_desktop_simulation()
            self.is_active = True
            if PYQT_AVAILABLE:
                self.sessionStarted.emit()
            return True
        
        # In a real implementation, this would initialize OpenXR
        # For now, we simulate
        self._initialize_views()
        self.is_active = True
        
        if PYQT_AVAILABLE:
            self.sessionStarted.emit()
        
        return True
    
    def end_session(self):
        """End XR session"""
        self.is_active = False
        
        if self._simulation_timer:
            self._simulation_timer.stop()
        
        if PYQT_AVAILABLE:
            self.sessionEnded.emit()
    
    def _start_desktop_simulation(self):
        """Start desktop mode simulation"""
        # Single view for desktop
        self.views = [
            XRView(
                eye="center",
                width=1920,
                height=1080,
                fov=(-45, 45, -30, 30)
            )
        ]
        
        self.views[0].calculate_projection()
        
        # Simulation update timer
        if PYQT_AVAILABLE:
            self._simulation_timer = QTimer()
            self._simulation_timer.timeout.connect(self._update_desktop_simulation)
            self._simulation_timer.start(16)  # ~60 FPS
    
    def _initialize_views(self):
        """Initialize stereoscopic views"""
        if self.mode in [XRMode.VR, XRMode.MIXED]:
            # Left eye
            left_view = XRView(
                eye="left",
                width=1920,
                height=1920,
                fov=(-45, 45, -45, 45)
            )
            left_view.pose.position = (-0.032, 0, 0)  # IPD offset
            
            # Right eye
            right_view = XRView(
                eye="right",
                width=1920,
                height=1920,
                fov=(-45, 45, -45, 45)
            )
            right_view.pose.position = (0.032, 0, 0)  # IPD offset
            
            self.views = [left_view, right_view]
            
            for view in self.views:
                view.calculate_projection()
    
    def _update_desktop_simulation(self):
        """Update desktop simulation"""
        # Simulate slight head movement
        t = time.time()
        
        # Subtle breathing-like motion
        self.head_pose.position = (
            math.sin(t * 0.5) * 0.01,
            1.6 + math.sin(t * 0.3) * 0.005,  # Eye height
            math.cos(t * 0.5) * 0.01
        )
        
        if PYQT_AVAILABLE:
            self.poseUpdated.emit(self.head_pose)
    
    def update_head_pose(self, position: Tuple[float, float, float],
                         orientation: Tuple[float, float, float, float]):
        """Update head pose from tracking"""
        self.head_pose.position = position
        self.head_pose.orientation = orientation
        
        # Update view poses
        for view in self.views:
            view.calculate_view()
        
        if PYQT_AVAILABLE:
            self.poseUpdated.emit(self.head_pose)
    
    def update_hand(self, hand_type: HandType, state: HandState):
        """Update hand tracking state"""
        if hand_type == HandType.LEFT:
            self.left_hand = state
        else:
            self.right_hand = state
        
        # Detect gestures
        self._detect_gestures(state)
    
    def _detect_gestures(self, hand: HandState):
        """Detect gestures from hand state"""
        old_gesture = hand.current_gesture
        new_gesture = GestureType.NONE
        confidence = 0.0
        
        # Analyze finger curl
        if hand.finger_curl:
            thumb = hand.finger_curl.get("thumb", 0)
            index = hand.finger_curl.get("index", 0)
            middle = hand.finger_curl.get("middle", 0)
            ring = hand.finger_curl.get("ring", 0)
            pinky = hand.finger_curl.get("pinky", 0)
            
            # Fist: all fingers curled
            if all(c > 0.8 for c in [index, middle, ring, pinky]):
                new_gesture = GestureType.FIST
                confidence = min(index, middle, ring, pinky)
            
            # Point: only index extended
            elif index < 0.3 and all(c > 0.7 for c in [middle, ring, pinky]):
                new_gesture = GestureType.POINT
                confidence = (1 - index) * min(middle, ring, pinky)
            
            # Open hand: all extended
            elif all(c < 0.3 for c in [index, middle, ring, pinky]):
                new_gesture = GestureType.OPEN
                confidence = 1 - max(index, middle, ring, pinky)
            
            # Thumbs up
            elif thumb < 0.3 and all(c > 0.7 for c in [index, middle, ring, pinky]):
                new_gesture = GestureType.THUMBS_UP
                confidence = (1 - thumb) * min(index, middle, ring, pinky)
        
        # Pinch detection
        if hand.pinch_strength > 0.7:
            new_gesture = GestureType.PINCH
            confidence = hand.pinch_strength
        
        # Grab detection
        elif hand.grab_strength > 0.7:
            new_gesture = GestureType.GRAB
            confidence = hand.grab_strength
        
        hand.current_gesture = new_gesture
        hand.gesture_confidence = confidence
        
        # Emit gesture change
        if new_gesture != old_gesture and confidence > 0.5:
            if PYQT_AVAILABLE:
                self.gestureDetected.emit(hand, new_gesture)
            
            # Call registered callbacks
            callbacks = self.gesture_callbacks.get(new_gesture, [])
            for callback in callbacks:
                callback(hand, new_gesture)
    
    def update_controller(self, hand_type: HandType, state: ControllerState):
        """Update controller state"""
        if hand_type == HandType.LEFT:
            self.left_controller = state
        else:
            self.right_controller = state
        
        if PYQT_AVAILABLE:
            self.controllerUpdated.emit(state)
    
    def register_gesture_callback(self, gesture: GestureType, callback: Callable):
        """Register callback for gesture detection"""
        if gesture not in self.gesture_callbacks:
            self.gesture_callbacks[gesture] = []
        self.gesture_callbacks[gesture].append(callback)
    
    def trigger_haptic(self, hand_type: HandType, amplitude: float = 0.5,
                       duration: float = 0.1):
        """Trigger haptic feedback"""
        controller = self.left_controller if hand_type == HandType.LEFT else self.right_controller
        controller.haptic_amplitude = amplitude
        controller.haptic_duration = duration
    
    def get_ray_from_controller(self, hand_type: HandType) -> Tuple[Tuple[float, float, float],
                                                                     Tuple[float, float, float]]:
        """Get ray origin and direction from controller"""
        controller = self.left_controller if hand_type == HandType.LEFT else self.right_controller
        
        origin = controller.pose.position
        direction = controller.pose.forward()
        
        return origin, direction
    
    def get_ray_from_hand(self, hand_type: HandType) -> Tuple[Tuple[float, float, float],
                                                               Tuple[float, float, float]]:
        """Get ray origin and direction from hand aim pose"""
        hand = self.left_hand if hand_type == HandType.LEFT else self.right_hand
        
        origin = hand.aim_pose.position
        direction = hand.aim_pose.forward()
        
        return origin, direction


class SpatialUI:
    """
    Spatial UI System for VR/AR
    
    Creates floating UI panels that exist in 3D space.
    """
    
    def __init__(self, session: XRSession):
        self.session = session
        self.panels: Dict[str, 'SpatialPanel'] = {}
    
    def create_panel(self, name: str, width: float = 1.0, height: float = 0.75,
                     position: Tuple[float, float, float] = (0, 1.5, -2)) -> 'SpatialPanel':
        """Create a spatial UI panel"""
        panel = SpatialPanel(name, width, height, position)
        self.panels[name] = panel
        return panel
    
    def remove_panel(self, name: str):
        """Remove a panel"""
        if name in self.panels:
            del self.panels[name]
    
    def get_panel(self, name: str) -> Optional['SpatialPanel']:
        """Get panel by name"""
        return self.panels.get(name)
    
    def update(self, dt: float):
        """Update all panels"""
        for panel in self.panels.values():
            panel.update(dt)
    
    def raycast(self, origin: Tuple[float, float, float],
                direction: Tuple[float, float, float]) -> Optional[Tuple['SpatialPanel', Tuple[float, float]]]:
        """Raycast against all panels, return hit panel and UV coordinates"""
        closest_hit = None
        closest_distance = float('inf')
        
        for panel in self.panels.values():
            hit = panel.raycast(origin, direction)
            if hit:
                distance, uv = hit
                if distance < closest_distance:
                    closest_distance = distance
                    closest_hit = (panel, uv)
        
        return closest_hit


@dataclass
class SpatialPanel:
    """
    A floating UI panel in 3D space
    """
    name: str
    width: float
    height: float
    position: Tuple[float, float, float]
    
    # Orientation (quaternion)
    orientation: Tuple[float, float, float, float] = (0, 0, 0, 1)
    
    # Visual
    opacity: float = 0.9
    corner_radius: float = 0.02
    background_color: Tuple[float, float, float, float] = (0.1, 0.1, 0.15, 0.9)
    border_color: Tuple[float, float, float, float] = (0.2, 0.8, 1.0, 1.0)
    
    # Interaction
    is_grabbable: bool = True
    is_scalable: bool = True
    look_at_user: bool = False
    
    # Content
    texture_id: int = 0
    render_callback: Optional[Callable] = None
    
    def update(self, dt: float):
        """Update panel"""
        if self.look_at_user:
            # Rotate panel to face user (billboard effect)
            # Assumes user/camera is at origin looking down -Z
            # Calculate direction from panel to user
            panel_pos = np.array(self.position)
            user_pos = np.array([0.0, panel_pos[1], 0.0])  # Keep same height
            
            direction = user_pos - panel_pos
            distance = np.linalg.norm(direction)
            
            if distance > 0.01:  # Avoid division by zero
                direction = direction / distance
                
                # Calculate yaw angle to face user
                yaw = np.arctan2(direction[0], direction[2])
                
                # Update orientation (quaternion from yaw)
                half_yaw = yaw / 2.0
                self.orientation = (
                    0.0,  # x
                    np.sin(half_yaw),  # y
                    0.0,  # z
                    np.cos(half_yaw)   # w
                )
    
    def raycast(self, origin: Tuple[float, float, float],
                direction: Tuple[float, float, float]) -> Optional[Tuple[float, Tuple[float, float]]]:
        """Check if ray intersects panel, return distance and UV coordinates"""
        # Simple plane intersection
        origin = np.array(origin)
        direction = np.array(direction)
        position = np.array(self.position)
        
        # Get panel normal (facing -Z in local space, transformed by orientation)
        pose = XRPose(self.position, self.orientation)
        normal = np.array(pose.forward())
        normal = -normal  # Face toward camera
        
        # Plane intersection
        denom = np.dot(normal, direction)
        if abs(denom) < 1e-6:
            return None
        
        t = np.dot(position - origin, normal) / denom
        if t < 0:
            return None
        
        # Intersection point
        hit_point = origin + direction * t
        
        # Convert to local coordinates
        local = hit_point - position
        
        # Get local axes
        right = np.array(pose.right())
        up = np.array(pose.up())
        
        u = np.dot(local, right)
        v = np.dot(local, up)
        
        # Check bounds
        if abs(u) > self.width / 2 or abs(v) > self.height / 2:
            return None
        
        # Normalize to 0-1 UV
        u = (u / self.width) + 0.5
        v = (v / self.height) + 0.5
        
        return (t, (u, v))
    
    def grab(self, controller_pose: XRPose):
        """Start grabbing the panel"""
        pass
    
    def release(self):
        """Release grabbed panel"""
        pass


class ImmersiveVisualization:
    """
    Immersive VR/AR visualization manager
    
    Coordinates 3D visualizations with XR session.
    """
    
    def __init__(self, session: XRSession):
        self.session = session
        self.spatial_ui = SpatialUI(session)
        
        # Visualization scale
        self.world_scale = 1.0  # 1:1 real world
        
        # Teleportation
        self.can_teleport = True
        self.teleport_target: Optional[Tuple[float, float, float]] = None
        
        # Grabbed objects
        self.grabbed_object: Optional[Any] = None
        self.grab_hand: Optional[HandType] = None
    
    def setup_default_panels(self):
        """Setup default UI panels"""
        # Main dashboard
        dashboard = self.spatial_ui.create_panel(
            "dashboard",
            width=2.0,
            height=1.2,
            position=(0, 1.5, -2)
        )
        dashboard.look_at_user = True
        
        # Left info panel
        info = self.spatial_ui.create_panel(
            "info",
            width=0.8,
            height=1.0,
            position=(-1.5, 1.5, -1.5)
        )
        
        # Right controls panel
        controls = self.spatial_ui.create_panel(
            "controls",
            width=0.8,
            height=1.0,
            position=(1.5, 1.5, -1.5)
        )
    
    def handle_grab(self, hand_type: HandType, is_grabbing: bool):
        """Handle grab gesture"""
        if is_grabbing and not self.grabbed_object:
            # Try to grab nearby object
            hand = self.session.left_hand if hand_type == HandType.LEFT else self.session.right_hand
            origin, direction = self.session.get_ray_from_hand(hand_type)
            
            # Check spatial UI panels
            hit = self.spatial_ui.raycast(origin, direction)
            if hit:
                panel, uv = hit
                if panel.is_grabbable:
                    self.grabbed_object = panel
                    self.grab_hand = hand_type
        
        elif not is_grabbing and self.grabbed_object:
            # Release grabbed object
            if isinstance(self.grabbed_object, SpatialPanel):
                self.grabbed_object.release()
            
            self.grabbed_object = None
            self.grab_hand = None
    
    def handle_point(self, hand_type: HandType):
        """Handle pointing gesture for selection"""
        origin, direction = self.session.get_ray_from_hand(hand_type)
        
        # Raycast against scene
        # This would integrate with the 3D visualization engine
        pass
    
    def teleport_to(self, position: Tuple[float, float, float]):
        """Teleport user to position"""
        if self.can_teleport:
            self.session.tracking_origin.position = position
    
    def scale_world(self, scale: float):
        """Scale the world (zoom in/out)"""
        self.world_scale = max(0.1, min(10.0, scale))
    
    def update(self, dt: float):
        """Update visualization"""
        self.spatial_ui.update(dt)
        
        # Update grabbed object position
        if self.grabbed_object and self.grab_hand:
            hand = self.session.left_hand if self.grab_hand == HandType.LEFT else self.session.right_hand
            
            if isinstance(self.grabbed_object, SpatialPanel):
                self.grabbed_object.position = hand.palm_pose.position
                self.grabbed_object.orientation = hand.palm_pose.orientation


# Export all public classes
__all__ = [
    'XRMode',
    'HandType',
    'GestureType',
    'XRPose',
    'HandJoint',
    'HandState',
    'ControllerState',
    'XRView',
    'XRSession',
    'SpatialUI',
    'SpatialPanel',
    'ImmersiveVisualization'
]
