"""
Plugin System Architecture
Extensible plugin framework for HydraRecon
"""

import asyncio
import importlib
import importlib.util
import inspect
import json
import os
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Type
import hashlib
import logging

logger = logging.getLogger(__name__)


class PluginType(Enum):
    """Types of plugins"""
    SCANNER = "scanner"
    EXPLOIT = "exploit"
    REPORTER = "reporter"
    INTEGRATION = "integration"
    ANALYZER = "analyzer"
    VISUALIZATION = "visualization"
    AUTOMATION = "automation"
    CUSTOM = "custom"


class PluginStatus(Enum):
    """Plugin status states"""
    INSTALLED = "installed"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"
    UPDATING = "updating"


@dataclass
class PluginInfo:
    """Plugin metadata"""
    id: str
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    entry_point: str
    dependencies: List[str] = field(default_factory=list)
    min_app_version: str = "1.0.0"
    homepage: str = ""
    license: str = "MIT"
    tags: List[str] = field(default_factory=list)
    icon: str = ""
    status: PluginStatus = PluginStatus.INSTALLED


@dataclass
class PluginHook:
    """Plugin hook point definition"""
    name: str
    description: str
    parameters: Dict[str, type] = field(default_factory=dict)
    return_type: type = None
    is_async: bool = False


class PluginBase(ABC):
    """
    Base class for all plugins.
    All plugins must inherit from this class.
    """
    
    # Plugin metadata - override in subclass
    PLUGIN_INFO = PluginInfo(
        id="base-plugin",
        name="Base Plugin",
        version="1.0.0",
        description="Base plugin class",
        author="Unknown",
        plugin_type=PluginType.CUSTOM,
        entry_point="plugin.Plugin"
    )
    
    def __init__(self, context: 'PluginContext'):
        self.context = context
        self._initialized = False
        self._hooks: Dict[str, Callable] = {}
    
    @abstractmethod
    async def initialize(self) -> bool:
        """
        Initialize the plugin.
        Called when the plugin is first loaded.
        Returns True if successful.
        """
        pass
    
    @abstractmethod
    async def shutdown(self) -> None:
        """
        Clean up plugin resources.
        Called when the plugin is being unloaded.
        """
        pass
    
    def register_hook(self, hook_name: str, callback: Callable) -> None:
        """Register a callback for a hook"""
        self._hooks[hook_name] = callback
    
    def get_hooks(self) -> Dict[str, Callable]:
        """Get all registered hooks"""
        return self._hooks
    
    @classmethod
    def get_info(cls) -> PluginInfo:
        """Get plugin metadata"""
        return cls.PLUGIN_INFO
    
    def get_config(self) -> Dict[str, Any]:
        """Get plugin configuration"""
        return self.context.get_plugin_config(self.PLUGIN_INFO.id)
    
    def save_config(self, config: Dict[str, Any]) -> None:
        """Save plugin configuration"""
        self.context.save_plugin_config(self.PLUGIN_INFO.id, config)
    
    def log(self, message: str, level: str = "info") -> None:
        """Log a message from the plugin"""
        self.context.log(f"[{self.PLUGIN_INFO.id}] {message}", level)


class ScannerPlugin(PluginBase):
    """Base class for scanner plugins"""
    
    PLUGIN_INFO = PluginInfo(
        id="scanner-plugin",
        name="Scanner Plugin",
        version="1.0.0",
        description="Base scanner plugin",
        author="Unknown",
        plugin_type=PluginType.SCANNER,
        entry_point="plugin.ScannerPlugin"
    )
    
    @abstractmethod
    async def scan(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a scan on the target.
        Returns scan results as a dictionary.
        """
        pass
    
    @abstractmethod
    def get_scan_options(self) -> List[Dict[str, Any]]:
        """
        Get available scan options.
        Returns list of option definitions.
        """
        pass


class ExploitPlugin(PluginBase):
    """Base class for exploit plugins"""
    
    PLUGIN_INFO = PluginInfo(
        id="exploit-plugin",
        name="Exploit Plugin",
        version="1.0.0",
        description="Base exploit plugin",
        author="Unknown",
        plugin_type=PluginType.EXPLOIT,
        entry_point="plugin.ExploitPlugin"
    )
    
    @abstractmethod
    async def check_vulnerable(self, target: str) -> bool:
        """Check if target is vulnerable"""
        pass
    
    @abstractmethod
    async def exploit(self, target: str, options: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the exploit"""
        pass
    
    @abstractmethod
    def get_exploit_info(self) -> Dict[str, Any]:
        """Get exploit details (CVE, severity, etc.)"""
        pass


class ReporterPlugin(PluginBase):
    """Base class for reporter plugins"""
    
    PLUGIN_INFO = PluginInfo(
        id="reporter-plugin",
        name="Reporter Plugin",
        version="1.0.0",
        description="Base reporter plugin",
        author="Unknown",
        plugin_type=PluginType.REPORTER,
        entry_point="plugin.ReporterPlugin"
    )
    
    @abstractmethod
    async def generate_report(self, data: Dict[str, Any], 
                              template: str = "default") -> str:
        """Generate a report from scan data"""
        pass
    
    @abstractmethod
    def get_templates(self) -> List[str]:
        """Get available report templates"""
        pass
    
    @abstractmethod
    def get_output_formats(self) -> List[str]:
        """Get supported output formats (pdf, html, json, etc.)"""
        pass


class IntegrationPlugin(PluginBase):
    """Base class for integration plugins (Burp, Metasploit, etc.)"""
    
    PLUGIN_INFO = PluginInfo(
        id="integration-plugin",
        name="Integration Plugin",
        version="1.0.0",
        description="Base integration plugin",
        author="Unknown",
        plugin_type=PluginType.INTEGRATION,
        entry_point="plugin.IntegrationPlugin"
    )
    
    @abstractmethod
    async def connect(self, config: Dict[str, Any]) -> bool:
        """Connect to external tool"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Disconnect from external tool"""
        pass
    
    @abstractmethod
    async def sync_data(self, direction: str = "both") -> Dict[str, Any]:
        """Sync data with external tool"""
        pass
    
    @abstractmethod
    def is_connected(self) -> bool:
        """Check if connected"""
        pass


class PluginContext:
    """
    Context object passed to plugins.
    Provides access to application functionality.
    """
    
    def __init__(self, app_config: Dict[str, Any], 
                 database: Any = None,
                 event_bus: 'EventBus' = None):
        self.app_config = app_config
        self.database = database
        self.event_bus = event_bus
        self._plugin_configs: Dict[str, Dict] = {}
        self._shared_data: Dict[str, Any] = {}
    
    def get_plugin_config(self, plugin_id: str) -> Dict[str, Any]:
        """Get configuration for a plugin"""
        return self._plugin_configs.get(plugin_id, {})
    
    def save_plugin_config(self, plugin_id: str, config: Dict[str, Any]) -> None:
        """Save plugin configuration"""
        self._plugin_configs[plugin_id] = config
    
    def get_shared_data(self, key: str) -> Any:
        """Get shared data accessible to all plugins"""
        return self._shared_data.get(key)
    
    def set_shared_data(self, key: str, value: Any) -> None:
        """Set shared data"""
        self._shared_data[key] = value
    
    def emit_event(self, event_name: str, data: Any = None) -> None:
        """Emit an event through the event bus"""
        if self.event_bus:
            self.event_bus.emit(event_name, data)
    
    def log(self, message: str, level: str = "info") -> None:
        """Log a message"""
        getattr(logger, level)(message)
    
    def get_targets(self) -> List[str]:
        """Get current targets from database"""
        if self.database:
            # Return targets from database
            return []
        return []
    
    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Add a finding to the database"""
        if self.database:
            pass  # Add to database
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service"""
        return self.app_config.get(f'{service}_api_key')


class EventBus:
    """Event bus for plugin communication"""
    
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = {}
    
    def subscribe(self, event_name: str, callback: Callable) -> None:
        """Subscribe to an event"""
        if event_name not in self._subscribers:
            self._subscribers[event_name] = []
        self._subscribers[event_name].append(callback)
    
    def unsubscribe(self, event_name: str, callback: Callable) -> None:
        """Unsubscribe from an event"""
        if event_name in self._subscribers:
            self._subscribers[event_name].remove(callback)
    
    def emit(self, event_name: str, data: Any = None) -> None:
        """Emit an event to all subscribers"""
        if event_name in self._subscribers:
            for callback in self._subscribers[event_name]:
                try:
                    if asyncio.iscoroutinefunction(callback):
                        asyncio.create_task(callback(data))
                    else:
                        callback(data)
                except Exception as e:
                    logger.error(f"Error in event handler for {event_name}: {e}")


class PluginManager:
    """
    Central plugin management system.
    Handles loading, enabling, disabling, and unloading plugins.
    """
    
    # Available hook points
    HOOKS = {
        "before_scan": PluginHook(
            name="before_scan",
            description="Called before a scan starts",
            parameters={"target": str, "options": dict},
            is_async=True
        ),
        "after_scan": PluginHook(
            name="after_scan",
            description="Called after a scan completes",
            parameters={"target": str, "results": dict},
            is_async=True
        ),
        "on_finding": PluginHook(
            name="on_finding",
            description="Called when a finding is discovered",
            parameters={"finding": dict},
            is_async=True
        ),
        "on_target_added": PluginHook(
            name="on_target_added",
            description="Called when a new target is added",
            parameters={"target": str},
            is_async=False
        ),
        "before_report": PluginHook(
            name="before_report",
            description="Called before report generation",
            parameters={"data": dict},
            is_async=True
        ),
        "after_report": PluginHook(
            name="after_report",
            description="Called after report generation",
            parameters={"report": str, "format": str},
            is_async=True
        ),
        "on_startup": PluginHook(
            name="on_startup",
            description="Called when application starts",
            parameters={},
            is_async=True
        ),
        "on_shutdown": PluginHook(
            name="on_shutdown",
            description="Called when application shuts down",
            parameters={},
            is_async=True
        ),
    }
    
    def __init__(self, plugins_dir: str = "plugins", 
                 context: Optional[PluginContext] = None):
        self.plugins_dir = Path(plugins_dir)
        self.plugins_dir.mkdir(parents=True, exist_ok=True)
        
        self.context = context or PluginContext({})
        self.event_bus = EventBus()
        self.context.event_bus = self.event_bus
        
        self._plugins: Dict[str, PluginBase] = {}
        self._plugin_modules: Dict[str, Any] = {}
        self._enabled_plugins: Set[str] = set()
        self._hook_handlers: Dict[str, List[Callable]] = {
            hook: [] for hook in self.HOOKS
        }
        
        # Load plugin registry
        self._registry_path = self.plugins_dir / "registry.json"
        self._registry = self._load_registry()
    
    def _load_registry(self) -> Dict[str, Any]:
        """Load plugin registry from file"""
        if self._registry_path.exists():
            try:
                with open(self._registry_path) as f:
                    return json.load(f)
            except Exception:
                pass
        return {"plugins": {}, "enabled": []}
    
    def _save_registry(self) -> None:
        """Save plugin registry to file"""
        with open(self._registry_path, 'w') as f:
            json.dump(self._registry, f, indent=2)
    
    async def discover_plugins(self) -> List[PluginInfo]:
        """Discover available plugins in the plugins directory"""
        discovered = []
        
        for plugin_path in self.plugins_dir.iterdir():
            if plugin_path.is_dir() and not plugin_path.name.startswith('_'):
                manifest_path = plugin_path / "manifest.json"
                if manifest_path.exists():
                    try:
                        with open(manifest_path) as f:
                            manifest = json.load(f)
                        
                        info = PluginInfo(
                            id=manifest['id'],
                            name=manifest['name'],
                            version=manifest['version'],
                            description=manifest.get('description', ''),
                            author=manifest.get('author', 'Unknown'),
                            plugin_type=PluginType(manifest.get('type', 'custom')),
                            entry_point=manifest.get('entry_point', 'plugin.Plugin'),
                            dependencies=manifest.get('dependencies', []),
                            min_app_version=manifest.get('min_app_version', '1.0.0'),
                            homepage=manifest.get('homepage', ''),
                            license=manifest.get('license', 'MIT'),
                            tags=manifest.get('tags', []),
                            icon=manifest.get('icon', '')
                        )
                        discovered.append(info)
                    except Exception as e:
                        logger.error(f"Error loading plugin manifest at {manifest_path}: {e}")
        
        return discovered
    
    async def load_plugin(self, plugin_id: str) -> bool:
        """Load a plugin by ID"""
        if plugin_id in self._plugins:
            logger.warning(f"Plugin {plugin_id} is already loaded")
            return True
        
        plugin_path = self.plugins_dir / plugin_id
        if not plugin_path.exists():
            logger.error(f"Plugin directory not found: {plugin_path}")
            return False
        
        manifest_path = plugin_path / "manifest.json"
        if not manifest_path.exists():
            logger.error(f"Plugin manifest not found: {manifest_path}")
            return False
        
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            
            # Add plugin path to sys.path
            sys.path.insert(0, str(plugin_path))
            
            # Import the plugin module
            entry_point = manifest.get('entry_point', 'plugin.Plugin')
            module_name, class_name = entry_point.rsplit('.', 1)
            
            spec = importlib.util.spec_from_file_location(
                module_name,
                plugin_path / f"{module_name.replace('.', '/')}.py"
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Get the plugin class
            plugin_class = getattr(module, class_name)
            
            # Verify it's a valid plugin
            if not issubclass(plugin_class, PluginBase):
                logger.error(f"Plugin {plugin_id} does not inherit from PluginBase")
                return False
            
            # Create plugin instance
            plugin = plugin_class(self.context)
            
            # Initialize the plugin
            if await plugin.initialize():
                self._plugins[plugin_id] = plugin
                self._plugin_modules[plugin_id] = module
                
                # Register plugin hooks
                for hook_name, callback in plugin.get_hooks().items():
                    if hook_name in self._hook_handlers:
                        self._hook_handlers[hook_name].append(callback)
                
                logger.info(f"Plugin {plugin_id} loaded successfully")
                return True
            else:
                logger.error(f"Plugin {plugin_id} failed to initialize")
                return False
            
        except Exception as e:
            logger.error(f"Error loading plugin {plugin_id}: {e}")
            return False
        finally:
            # Remove plugin path from sys.path
            if str(plugin_path) in sys.path:
                sys.path.remove(str(plugin_path))
    
    async def unload_plugin(self, plugin_id: str) -> bool:
        """Unload a plugin"""
        if plugin_id not in self._plugins:
            logger.warning(f"Plugin {plugin_id} is not loaded")
            return True
        
        try:
            plugin = self._plugins[plugin_id]
            
            # Remove hook handlers
            for hook_name, callback in plugin.get_hooks().items():
                if callback in self._hook_handlers.get(hook_name, []):
                    self._hook_handlers[hook_name].remove(callback)
            
            # Shutdown the plugin
            await plugin.shutdown()
            
            # Remove from loaded plugins
            del self._plugins[plugin_id]
            del self._plugin_modules[plugin_id]
            
            if plugin_id in self._enabled_plugins:
                self._enabled_plugins.remove(plugin_id)
            
            logger.info(f"Plugin {plugin_id} unloaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error unloading plugin {plugin_id}: {e}")
            return False
    
    async def enable_plugin(self, plugin_id: str) -> bool:
        """Enable a plugin"""
        if plugin_id not in self._plugins:
            if not await self.load_plugin(plugin_id):
                return False
        
        self._enabled_plugins.add(plugin_id)
        self._registry['enabled'] = list(self._enabled_plugins)
        self._save_registry()
        
        logger.info(f"Plugin {plugin_id} enabled")
        return True
    
    async def disable_plugin(self, plugin_id: str) -> bool:
        """Disable a plugin"""
        if plugin_id in self._enabled_plugins:
            self._enabled_plugins.remove(plugin_id)
            self._registry['enabled'] = list(self._enabled_plugins)
            self._save_registry()
        
        logger.info(f"Plugin {plugin_id} disabled")
        return True
    
    def get_plugin(self, plugin_id: str) -> Optional[PluginBase]:
        """Get a loaded plugin by ID"""
        return self._plugins.get(plugin_id)
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> List[PluginBase]:
        """Get all loaded plugins of a specific type"""
        return [
            p for p in self._plugins.values()
            if p.get_info().plugin_type == plugin_type
        ]
    
    def is_enabled(self, plugin_id: str) -> bool:
        """Check if a plugin is enabled"""
        return plugin_id in self._enabled_plugins
    
    async def execute_hook(self, hook_name: str, **kwargs) -> List[Any]:
        """Execute a hook and return results from all handlers"""
        if hook_name not in self.HOOKS:
            logger.warning(f"Unknown hook: {hook_name}")
            return []
        
        results = []
        hook_info = self.HOOKS[hook_name]
        
        for handler in self._hook_handlers.get(hook_name, []):
            try:
                if hook_info.is_async:
                    result = await handler(**kwargs)
                else:
                    result = handler(**kwargs)
                results.append(result)
            except Exception as e:
                logger.error(f"Error in hook handler {hook_name}: {e}")
        
        return results
    
    async def install_plugin(self, source: str) -> bool:
        """Install a plugin from a source (path, URL, or package name)"""
        try:
            if source.startswith(('http://', 'https://')):
                # Download from URL
                return await self._install_from_url(source)
            elif os.path.exists(source):
                # Install from local path
                return await self._install_from_path(source)
            else:
                # Assume it's a plugin ID from marketplace
                return await self._install_from_marketplace(source)
        except Exception as e:
            logger.error(f"Error installing plugin from {source}: {e}")
            return False
    
    async def _install_from_path(self, path: str) -> bool:
        """Install plugin from local path"""
        source_path = Path(path)
        
        if not source_path.exists():
            return False
        
        manifest_path = source_path / "manifest.json"
        if not manifest_path.exists():
            logger.error("Plugin manifest.json not found")
            return False
        
        with open(manifest_path) as f:
            manifest = json.load(f)
        
        plugin_id = manifest['id']
        dest_path = self.plugins_dir / plugin_id
        
        # Copy plugin files
        import shutil
        if dest_path.exists():
            shutil.rmtree(dest_path)
        shutil.copytree(source_path, dest_path)
        
        # Update registry
        self._registry['plugins'][plugin_id] = {
            'installed_at': datetime.now().isoformat(),
            'version': manifest['version'],
            'source': str(path)
        }
        self._save_registry()
        
        logger.info(f"Plugin {plugin_id} installed from {path}")
        return True
    
    async def _install_from_url(self, url: str) -> bool:
        """Install plugin from URL"""
        # TODO: Implement URL download and install
        return False
    
    async def _install_from_marketplace(self, plugin_id: str) -> bool:
        """Install plugin from marketplace"""
        # TODO: Implement marketplace integration
        return False
    
    async def uninstall_plugin(self, plugin_id: str) -> bool:
        """Uninstall a plugin"""
        # First unload if loaded
        if plugin_id in self._plugins:
            await self.unload_plugin(plugin_id)
        
        plugin_path = self.plugins_dir / plugin_id
        if plugin_path.exists():
            import shutil
            shutil.rmtree(plugin_path)
        
        if plugin_id in self._registry['plugins']:
            del self._registry['plugins'][plugin_id]
            self._save_registry()
        
        logger.info(f"Plugin {plugin_id} uninstalled")
        return True
    
    async def update_plugin(self, plugin_id: str) -> bool:
        """Update a plugin to the latest version"""
        # TODO: Implement plugin update
        return False
    
    async def load_enabled_plugins(self) -> None:
        """Load all enabled plugins from registry"""
        for plugin_id in self._registry.get('enabled', []):
            try:
                await self.load_plugin(plugin_id)
                self._enabled_plugins.add(plugin_id)
            except Exception as e:
                logger.error(f"Failed to load enabled plugin {plugin_id}: {e}")
    
    def get_available_hooks(self) -> Dict[str, PluginHook]:
        """Get all available hooks"""
        return self.HOOKS.copy()


# Example plugin template
PLUGIN_TEMPLATE = '''
"""
{plugin_name} Plugin
{description}
"""

from core.plugin_system import PluginBase, PluginInfo, PluginType, PluginContext
from typing import Dict, Any


class {class_name}(PluginBase):
    """
    {description}
    """
    
    PLUGIN_INFO = PluginInfo(
        id="{plugin_id}",
        name="{plugin_name}",
        version="1.0.0",
        description="{description}",
        author="{author}",
        plugin_type=PluginType.{plugin_type},
        entry_point="plugin.{class_name}"
    )
    
    def __init__(self, context: PluginContext):
        super().__init__(context)
        self.register_hook("before_scan", self.on_before_scan)
    
    async def initialize(self) -> bool:
        """Initialize the plugin"""
        self.log("Plugin initialized")
        return True
    
    async def shutdown(self) -> None:
        """Cleanup plugin resources"""
        self.log("Plugin shutting down")
    
    async def on_before_scan(self, target: str, options: dict) -> None:
        """Hook called before each scan"""
        self.log(f"Scan starting for target: {{target}}")
'''


def create_plugin_template(plugin_id: str, plugin_name: str,
                           description: str, author: str,
                           plugin_type: str = "CUSTOM") -> str:
    """Generate a plugin template"""
    class_name = ''.join(word.capitalize() for word in plugin_name.split())
    
    return PLUGIN_TEMPLATE.format(
        plugin_id=plugin_id,
        plugin_name=plugin_name,
        description=description,
        author=author,
        plugin_type=plugin_type,
        class_name=class_name
    )
