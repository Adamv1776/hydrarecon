#!/usr/bin/env python3
"""
ESP32 Mesh WiFi Sensing - Live Environment Reconstruction & People Tracking

This script connects to the dual-ESP32 mesh sensing system and provides:
- Real-time environment reconstruction from WiFi signals
- Multi-node triangulation for accurate localization
- Person detection and activity tracking
- 3D visualization of the reconstructed space

Usage:
    python esp32_sensing_launcher.py [--host 192.168.4.1] [--visualize]

Prerequisites:
    - Primary ESP32-S3 running HydraSense firmware (creates WiFi AP)
    - Remote ESP32 running remote firmware (connects to HydraSense)
    - This computer connected to HydraSense WiFi network

Copyright (c) 2024-2025 HydraRecon Security Suite
"""

import asyncio
import sys
import os
import time
import json
import threading
import signal
from datetime import datetime
from typing import Optional, Dict, Any, List

# Add parent dir to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np

try:
    from core.esp32_mesh_sensing import (
        ESP32MeshSensing, TrackedPerson, WiFiDetection,
        ActivityType, EnvironmentReconstructor
    )
except ImportError as e:
    print(f"Error importing ESP32 mesh sensing module: {e}")
    sys.exit(1)


# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


class TerminalVisualizer:
    """
    ASCII-based real-time visualization for terminal.
    
    Shows:
    - Room layout with signal heatmap
    - Person positions
    - Activity status
    - Statistics
    """
    
    def __init__(self, room_width: float = 8.0, room_depth: float = 8.0):
        self.room_width = room_width
        self.room_depth = room_depth
        self.grid_width = 40  # ASCII characters
        self.grid_height = 20
        self.frame_count = 0
        
    def clear_screen(self):
        """Clear terminal screen."""
        print('\033[2J\033[H', end='')
        
    def render(self, persons: List[Dict[str, Any]], 
               macs: List[Dict[str, Any]],
               status: Dict[str, Any],
               heatmap: Optional[np.ndarray] = None):
        """Render a frame to terminal."""
        self.clear_screen()
        self.frame_count += 1
        
        lines = []
        
        # Header
        lines.append(f"{Colors.CYAN}{Colors.BOLD}")
        lines.append("╔══════════════════════════════════════════════════════════════════════════════╗")
        lines.append("║     🛰️  ESP32 MESH WIFI SENSING - ENVIRONMENT RECONSTRUCTION                 ║")
        lines.append("╠══════════════════════════════════════════════════════════════════════════════╣")
        lines.append(f"{Colors.RESET}")
        
        # Status bar
        uptime = int(status.get('uptime_seconds', 0))
        mins, secs = divmod(uptime, 60)
        hours, mins = divmod(mins, 60)
        
        status_line = (
            f"{Colors.GREEN}● Primary: {'CONNECTED' if status.get('primary_connected') else 'DISCONNECTED'}{Colors.RESET} │ "
            f"{Colors.BLUE}Remotes: {status.get('remote_nodes', 0)}{Colors.RESET} │ "
            f"Packets: {status.get('packets_received', 0):,} │ "
            f"Uptime: {hours:02d}:{mins:02d}:{secs:02d}"
        )
        lines.append(f"║ {status_line:<85} ║")
        lines.append("╠═══════════════════════════════════════╦══════════════════════════════════════╣")
        
        # Create room grid
        grid = [[' ' for _ in range(self.grid_width)] for _ in range(self.grid_height)]
        
        # Draw room boundary
        for x in range(self.grid_width):
            grid[0][x] = '─'
            grid[self.grid_height - 1][x] = '─'
        for y in range(self.grid_height):
            grid[y][0] = '│'
            grid[y][self.grid_width - 1] = '│'
        grid[0][0] = '┌'
        grid[0][self.grid_width - 1] = '┐'
        grid[self.grid_height - 1][0] = '└'
        grid[self.grid_height - 1][self.grid_width - 1] = '┘'
        
        # Mark node positions
        # Primary at left side
        primary_x, primary_y = 2, self.grid_height // 2
        grid[primary_y][primary_x] = f'{Colors.GREEN}◆{Colors.RESET}'
        
        # Remote at right side (~15ft away)
        remote_x, remote_y = self.grid_width - 3, self.grid_height // 2
        grid[remote_y][remote_x] = f'{Colors.BLUE}◇{Colors.RESET}'
        
        # Draw heatmap if available
        if heatmap is not None and heatmap.size > 0:
            heat_chars = ' ░▒▓█'
            hm_h, hm_w = heatmap.shape
            max_val = np.max(heatmap) if np.max(heatmap) > 0 else 1
            
            for gy in range(1, self.grid_height - 1):
                for gx in range(1, self.grid_width - 1):
                    hm_x = int((gx - 1) / (self.grid_width - 2) * hm_w)
                    hm_y = int((gy - 1) / (self.grid_height - 2) * hm_h)
                    hm_x = min(hm_x, hm_w - 1)
                    hm_y = min(hm_y, hm_h - 1)
                    
                    val = heatmap[hm_y, hm_x] / max_val
                    char_idx = int(val * (len(heat_chars) - 1))
                    if char_idx > 0:
                        grid[gy][gx] = f'{Colors.DIM}{heat_chars[char_idx]}{Colors.RESET}'
        
        # Draw persons
        activity_icons = {
            'idle': '🧍',
            'standing': '🧍',
            'walking': '🚶',
            'running': '🏃',
            'sitting': '🪑',
            'fallen': '⚠️',
            'unknown': '❓'
        }
        
        for i, person in enumerate(persons):
            pos = person.get('position', {})
            px = int((pos.get('x', 0) / self.room_width) * (self.grid_width - 2)) + 1
            py = int((pos.get('y', 0) / self.room_depth) * (self.grid_height - 2)) + 1
            
            px = max(1, min(px, self.grid_width - 2))
            py = max(1, min(py, self.grid_height - 2))
            
            activity = person.get('activity', 'unknown')
            icon = activity_icons.get(activity, '●')
            confidence = person.get('confidence', 0)
            
            if confidence > 0.7:
                color = Colors.GREEN
            elif confidence > 0.4:
                color = Colors.YELLOW
            else:
                color = Colors.RED
                
            grid[py][px] = f'{color}{icon}{Colors.RESET}'
        
        # Render grid with info panel
        info_panel_lines = self._create_info_panel(persons, macs, status)
        
        for i in range(self.grid_height):
            row = ''.join(grid[i])
            info = info_panel_lines[i] if i < len(info_panel_lines) else ''
            lines.append(f"║ {row} ║{info:36}║")
        
        lines.append("╠═══════════════════════════════════════╩══════════════════════════════════════╣")
        
        # Legend
        legend = (
            f"║ {Colors.GREEN}◆{Colors.RESET} Primary ESP32  "
            f"{Colors.BLUE}◇{Colors.RESET} Remote ESP32  "
            f"🧍 Person  "
            f"░▒▓ Signal Strength  "
            f"[Frame: {self.frame_count}]"
        )
        lines.append(f"{legend:<89}║")
        lines.append("╚══════════════════════════════════════════════════════════════════════════════╝")
        
        print('\n'.join(lines))
        
    def _create_info_panel(self, persons: List[Dict[str, Any]], 
                           macs: List[Dict[str, Any]],
                           status: Dict[str, Any]) -> List[str]:
        """Create right-side info panel content."""
        lines = []
        
        # Detected persons section
        lines.append(f" {Colors.BOLD}DETECTED PERSONS{Colors.RESET} ")
        lines.append("─" * 35)
        
        if persons:
            for p in persons[:5]:  # Show up to 5
                pos = p.get('position', {})
                vel = p.get('velocity', {})
                speed = (vel.get('x', 0)**2 + vel.get('y', 0)**2)**0.5
                
                activity = p.get('activity', 'unknown')
                conf = p.get('confidence', 0) * 100
                
                lines.append(f" {p.get('id', '?')}: ({pos.get('x', 0):.1f}, {pos.get('y', 0):.1f})m ")
                lines.append(f"   Activity: {activity:<10} Conf: {conf:.0f}%")
                lines.append(f"   Speed: {speed:.2f} m/s")
        else:
            lines.append(f" {Colors.DIM}No persons detected{Colors.RESET}")
            lines.append("")
            lines.append("")
        
        lines.append("")
        lines.append(f" {Colors.BOLD}TRACKED DEVICES{Colors.RESET} ")
        lines.append("─" * 35)
        
        active_macs = [m for m in macs if m.get('active', False)]
        if active_macs:
            for m in active_macs[:4]:
                mac = m.get('mac', 'Unknown')[-8:]  # Last 8 chars
                rssi = m.get('avg_rssi', -100)
                count = m.get('detection_count', 0)
                
                rssi_bar = self._rssi_bar(rssi)
                lines.append(f" ...{mac} {rssi_bar} {rssi:.0f}dBm")
        else:
            lines.append(f" {Colors.DIM}No active devices{Colors.RESET}")
        
        # Pad to match grid height
        while len(lines) < self.grid_height:
            lines.append("")
            
        return lines
        
    def _rssi_bar(self, rssi: float, width: int = 6) -> str:
        """Create RSSI strength bar."""
        # Map -90 to -30 dBm to 0-100%
        normalized = max(0, min(1, (rssi + 90) / 60))
        filled = int(normalized * width)
        
        if normalized > 0.6:
            color = Colors.GREEN
        elif normalized > 0.3:
            color = Colors.YELLOW
        else:
            color = Colors.RED
            
        return f"{color}{'█' * filled}{'░' * (width - filled)}{Colors.RESET}"


class ESP32SensingLauncher:
    """Main launcher for the ESP32 mesh sensing system."""
    
    def __init__(self, host: str = "192.168.4.1", 
                 room_size: tuple = (8.0, 8.0, 3.0),
                 visualize: bool = True):
        self.host = host
        self.room_size = room_size
        self.visualize = visualize
        
        self.sensing: Optional[ESP32MeshSensing] = None
        self.visualizer: Optional[TerminalVisualizer] = None
        self.running = False
        
        # Data for visualization
        self.current_persons: List[Dict[str, Any]] = []
        self.current_macs: List[Dict[str, Any]] = []
        self.current_status: Dict[str, Any] = {}
        self.current_heatmap: Optional[np.ndarray] = None
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        print(f"\n{Colors.YELLOW}Shutting down...{Colors.RESET}")
        self.stop()
        sys.exit(0)
        
    async def start(self):
        """Start the sensing system."""
        print(f"{Colors.CYAN}{Colors.BOLD}")
        print("=" * 60)
        print("   ESP32 MESH WIFI SENSING SYSTEM")
        print("   Environment Reconstruction & People Tracking")
        print("=" * 60)
        print(f"{Colors.RESET}")
        
        print(f"\n{Colors.BLUE}[*] Initializing...{Colors.RESET}")
        print(f"    Primary Host: {self.host}")
        print(f"    Room Size: {self.room_size[0]}m x {self.room_size[1]}m x {self.room_size[2]}m")
        
        # Create sensing system
        self.sensing = ESP32MeshSensing(
            primary_host=self.host,
            room_size=self.room_size,
            node_separation=4.57  # ~15 feet
        )
        
        # Set callbacks
        self.sensing.on_person_update = self._on_persons_updated
        self.sensing.on_detection = self._on_detection
        
        # Initialize
        print(f"\n{Colors.BLUE}[*] Connecting to ESP32 mesh...{Colors.RESET}")
        
        if not await self.sensing.initialize():
            print(f"{Colors.RED}[!] Failed to connect to primary ESP32{Colors.RESET}")
            print(f"    Make sure you are connected to the HydraSense WiFi network")
            print(f"    and the ESP32-S3 is powered on.")
            return False
            
        print(f"{Colors.GREEN}[+] Connected to primary ESP32{Colors.RESET}")
        
        # Check for remote nodes
        status = self.sensing.get_status()
        if status.get('remote_nodes', 0) > 0:
            print(f"{Colors.GREEN}[+] Found {status['remote_nodes']} remote node(s){Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}[!] No remote nodes found - triangulation limited{Colors.RESET}")
            
        # Start sensing
        print(f"\n{Colors.BLUE}[*] Starting WiFi sensing...{Colors.RESET}")
        self.sensing.start()
        self.running = True
        
        # Create visualizer
        if self.visualize:
            self.visualizer = TerminalVisualizer(self.room_size[0], self.room_size[1])
            
        print(f"{Colors.GREEN}[+] System active - Press Ctrl+C to stop{Colors.RESET}\n")
        
        # Wait a moment for initial data
        await asyncio.sleep(2)
        
        # Main loop
        await self._main_loop()
        
        return True
        
    async def _main_loop(self):
        """Main update loop."""
        update_interval = 0.5  # 2 FPS for terminal
        
        while self.running:
            try:
                # Get current data
                self.current_status = self.sensing.get_status()
                self.current_persons = self.sensing.get_persons()
                self.current_macs = self.sensing.get_tracked_macs()
                
                env = self.sensing.get_environment()
                if 'signal_heatmap' in env:
                    hm = env['signal_heatmap']
                    if hm:
                        self.current_heatmap = np.array(hm)
                
                # Render
                if self.visualize and self.visualizer:
                    self.visualizer.render(
                        self.current_persons,
                        self.current_macs,
                        self.current_status,
                        self.current_heatmap
                    )
                else:
                    # Simple text output
                    self._print_status()
                    
                await asyncio.sleep(update_interval)
                
            except Exception as e:
                print(f"{Colors.RED}Error in main loop: {e}{Colors.RESET}")
                await asyncio.sleep(1)
                
    def _print_status(self):
        """Print simple status without visualization."""
        print(f"\r[{datetime.now().strftime('%H:%M:%S')}] "
              f"Packets: {self.current_status.get('packets_received', 0):,} | "
              f"Persons: {len(self.current_persons)} | "
              f"MACs: {len(self.current_macs)}", 
              end='', flush=True)
        
    def _on_persons_updated(self, persons: List[TrackedPerson]):
        """Callback when person tracking updates."""
        pass  # Data retrieved in main loop
        
    def _on_detection(self, detection: WiFiDetection):
        """Callback for each WiFi detection."""
        pass  # Handled by sensing system
        
    def stop(self):
        """Stop the sensing system."""
        self.running = False
        if self.sensing:
            self.sensing.stop()


async def check_network_connection(host: str) -> bool:
    """Check if we can reach the ESP32."""
    import socket
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((host, 80))
        sock.close()
        return result == 0
    except Exception:
        return False


async def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="ESP32 Mesh WiFi Sensing - Environment Reconstruction & People Tracking",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python esp32_sensing_launcher.py
  python esp32_sensing_launcher.py --host 192.168.4.1
  python esp32_sensing_launcher.py --no-visualize
  python esp32_sensing_launcher.py --room-width 10 --room-depth 10
        """
    )
    
    parser.add_argument("--host", default="192.168.4.1",
                        help="Primary ESP32 IP address (default: 192.168.4.1)")
    parser.add_argument("--room-width", type=float, default=8.0,
                        help="Room width in meters (default: 8.0)")
    parser.add_argument("--room-depth", type=float, default=8.0,
                        help="Room depth in meters (default: 8.0)")
    parser.add_argument("--room-height", type=float, default=3.0,
                        help="Room height in meters (default: 3.0)")
    parser.add_argument("--no-visualize", action="store_true",
                        help="Disable terminal visualization")
    
    args = parser.parse_args()
    
    # Check network first
    print(f"{Colors.BLUE}[*] Checking network connection to {args.host}...{Colors.RESET}")
    
    if not await check_network_connection(args.host):
        print(f"\n{Colors.RED}[!] Cannot reach ESP32 at {args.host}{Colors.RESET}")
        print(f"\n{Colors.YELLOW}Please ensure:{Colors.RESET}")
        print("  1. The ESP32-S3 is powered on and running the HydraSense firmware")
        print("  2. Your computer is connected to the 'HydraSense' WiFi network")
        print("     - Password: hydra2026!")
        print("  3. You have an IP address in the 192.168.4.x range")
        print(f"\nTry: ping {args.host}")
        return
        
    print(f"{Colors.GREEN}[+] Network connection OK{Colors.RESET}")
    
    # Launch
    launcher = ESP32SensingLauncher(
        host=args.host,
        room_size=(args.room_width, args.room_depth, args.room_height),
        visualize=not args.no_visualize
    )
    
    await launcher.start()


if __name__ == "__main__":
    asyncio.run(main())
