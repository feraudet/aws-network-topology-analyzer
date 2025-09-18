# Contributing to AWS Network Discovery and Analysis Tool

Thank you for your interest in contributing to the AWS Network Discovery and Analysis Tool! This document provides guidelines and information for contributors.

## Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Code Style](#code-style)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Issue Reporting](#issue-reporting)
- [Feature Requests](#feature-requests)

## Getting Started

### Prerequisites

- Python 3.8 or higher
- AWS CLI configured with SSO
- Git

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/axa/aws-network-discovery.git
   cd aws-network-discovery
   ```

2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -e .[dev]  # Install in development mode with dev dependencies
   ```

4. **Run tests to verify setup**
   ```bash
   pytest tests/ -v
   ```

## Code Style

We follow PEP 8 style guidelines with some specific conventions:

### Formatting
- Use **Black** for code formatting
- Maximum line length: 100 characters
- Use double quotes for strings
- Use type hints where appropriate

### Naming Conventions
- Classes: `PascalCase`
- Functions and variables: `snake_case`
- Constants: `UPPER_SNAKE_CASE`
- Private methods: `_leading_underscore`

### Documentation
- Use docstrings for all public classes and methods
- Follow Google-style docstrings
- Include type hints in function signatures

Example:
```python
def collect_resources(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Collect AWS resources from specified regions.
    
    Args:
        regions: List of AWS regions to collect from
        account_ids: Optional list of account IDs for cross-account access
        
    Returns:
        Dictionary containing collected resource data by region
        
    Raises:
        ClientError: If AWS API calls fail
        ValueError: If invalid parameters are provided
    """
```

### Code Quality Tools

Run these tools before submitting:

```bash
# Format code
black aws_network_discovery/ tests/

# Check style
flake8 aws_network_discovery/ tests/

# Type checking
mypy aws_network_discovery/

# Run all tests
pytest tests/ --cov=aws_network_discovery
```

## Testing

### Test Structure
- Unit tests in `tests/` directory
- Test files should match the module they're testing: `test_<module_name>.py`
- Use mocking for AWS API calls (moto library)

### Writing Tests
- Use pytest framework
- Mock external dependencies
- Test both success and failure scenarios
- Aim for high test coverage (>90%)

### Example Test
```python
import pytest
from unittest.mock import Mock, patch
from moto import mock_ec2

from aws_network_discovery.collectors.ec2_collector import EC2Collector

class TestEC2Collector:
    @mock_ec2
    def test_collect_instances(self):
        # Setup mock resources
        # ... test implementation
        pass
    
    def test_error_handling(self):
        # Test error scenarios
        # ... test implementation
        pass
```

### Running Tests
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_collectors.py

# Run with coverage
pytest --cov=aws_network_discovery --cov-report=html

# Run tests in parallel
pytest -n auto
```

## Submitting Changes

### Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following the style guidelines
   - Add tests for new functionality
   - Update documentation as needed

3. **Test your changes**
   ```bash
   pytest tests/
   black aws_network_discovery/ tests/
   flake8 aws_network_discovery/ tests/
   ```

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add new resource collector for RDS instances"
   ```

5. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   ```

### Commit Message Format

Use conventional commit format:
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation changes
- `test:` - Adding or updating tests
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `chore:` - Maintenance tasks

### PR Requirements

- [ ] All tests pass
- [ ] Code coverage maintained or improved
- [ ] Documentation updated
- [ ] CHANGELOG.md updated (for significant changes)
- [ ] No merge conflicts
- [ ] Descriptive PR title and description

## Issue Reporting

### Bug Reports

When reporting bugs, please include:

1. **Environment Information**
   - Python version
   - Operating system
   - AWS CLI version
   - Tool version

2. **Steps to Reproduce**
   - Exact commands run
   - Configuration used
   - Expected vs actual behavior

3. **Error Messages**
   - Full error traceback
   - Log files (with sensitive data removed)

4. **Additional Context**
   - AWS resources involved
   - Network topology details

### Bug Report Template
```markdown
## Bug Description
Brief description of the issue

## Environment
- Python version: 3.9.0
- OS: Ubuntu 20.04
- AWS CLI: 2.4.0
- Tool version: 1.0.0

## Steps to Reproduce
1. Run command: `python main.py discover --profile my-profile`
2. See error

## Expected Behavior
What should have happened

## Actual Behavior
What actually happened

## Error Messages
```
Paste error messages here
```

## Additional Context
Any other relevant information
```

## Feature Requests

### Before Submitting
- Check existing issues and PRs
- Consider if the feature fits the project scope
- Think about backward compatibility

### Feature Request Template
```markdown
## Feature Description
Clear description of the proposed feature

## Use Case
Why is this feature needed? What problem does it solve?

## Proposed Solution
How should this feature work?

## Alternatives Considered
Other approaches you've considered

## Additional Context
Any other relevant information
```

## Development Guidelines

### Adding New Collectors

When adding support for new AWS services:

1. **Create collector class**
   ```python
   class NewServiceCollector(BaseCollector):
       def get_resource_type(self) -> str:
           return 'new_service_resources'
       
       def collect(self, regions: List[str], account_ids: Optional[List[str]] = None) -> Dict[str, Any]:
           # Implementation
           pass
   ```

2. **Add to orchestrator**
   - Update `DiscoveryOrchestrator` to include new collector
   - Follow the bottom-up discovery order

3. **Update analysis**
   - Modify `NetworkAnalyzer` to handle new resource type
   - Add communication path logic if applicable

4. **Add tests**
   - Unit tests with mocking
   - Integration tests if needed

### Configuration Changes

When modifying configuration:

1. **Update dataclasses** in `config/settings.py`
2. **Add environment variable mapping**
3. **Update default configuration template**
4. **Add tests** for new configuration options
5. **Update documentation**

### Output Format Changes

When modifying report outputs:

1. **Update all generators** (JSON, CSV, Excel, HTML)
2. **Maintain backward compatibility** where possible
3. **Add configuration options** for new features
4. **Test with real data**
5. **Update examples**

## Release Process

### Version Numbering
We use semantic versioning (SemVer):
- `MAJOR.MINOR.PATCH`
- Major: Breaking changes
- Minor: New features (backward compatible)
- Patch: Bug fixes

### Release Checklist
- [ ] All tests pass
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version bumped in `setup.py` and `__init__.py`
- [ ] Git tag created
- [ ] Release notes prepared

## Getting Help

### Communication Channels
- GitHub Issues: Bug reports and feature requests
- GitHub Discussions: General questions and ideas
- Email: network-team@axa.com (for security issues)

### Documentation
- README.md: Basic usage and setup
- examples/: Usage examples
- Code comments: Implementation details

## Code of Conduct

### Our Standards
- Be respectful and inclusive
- Focus on constructive feedback
- Help others learn and grow
- Maintain professional communication

### Unacceptable Behavior
- Harassment or discrimination
- Trolling or insulting comments
- Publishing private information
- Other unprofessional conduct

### Enforcement
Violations may result in temporary or permanent ban from the project.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to the AWS Network Discovery and Analysis Tool! 🚀
