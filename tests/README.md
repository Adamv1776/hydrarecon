# HydraRecon Tests

This directory contains the test suite for HydraRecon.

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_core.py -v

# Run with coverage
python -m pytest tests/ -v --cov=core --cov=gui --cov=scanners

# Run integration tests
python -m pytest tests/test_integration.py -v
```

## Test Categories

- **test_core.py** - Unit tests for core modules
- **test_integration.py** - Integration tests for end-to-end functionality
- **test_security.py** - Security-specific tests (future)
- **test_gui.py** - GUI component tests (requires display or xvfb)

## Requirements

```bash
pip install pytest pytest-cov pytest-asyncio
```

## Writing New Tests

Follow the existing pattern:

```python
import unittest

class TestYourModule(unittest.TestCase):
    def setUp(self):
        # Setup code
        pass
    
    def tearDown(self):
        # Cleanup code
        pass
    
    def test_your_functionality(self):
        # Test code
        self.assertTrue(True)
```
