# Contributing to CyberVisionVAPT

Thank you for your interest in contributing to CyberVisionVAPT! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to:
- Use the tool responsibly and ethically
- Only test systems you own or have explicit permission to test
- Report security vulnerabilities responsibly
- Respect the work of other contributors

## How to Contribute

### Reporting Bugs

If you find a bug, please open an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version, etc.)

### Suggesting Enhancements

Feature requests are welcome! Please include:
- Clear description of the feature
- Use case and benefits
- Potential implementation approach

### Contributing Code

1. **Fork the repository**
2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the existing code style
   - Add comments where necessary
   - Update documentation if needed

4. **Test your changes**
   - Ensure existing functionality still works
   - Add tests for new features

5. **Commit your changes**
   ```bash
   git commit -m "Add feature: brief description"
   ```

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Submit a pull request**

## Development Guidelines

### Code Style

- Follow PEP 8 for Python code
- Use descriptive variable and function names
- Add docstrings to all functions and classes
- Keep functions focused and modular

### Adding New Modules

When adding new scanning modules:
1. Create file in `cybervision/modules/`
2. Follow existing module structure
3. Add appropriate error handling
4. Include detailed docstrings
5. Update README with new features

### Adding Vulnerabilities

To add new vulnerability checks:
1. Update `vuln_scanner.py` database
2. Include CVE identifier
3. Add severity rating
4. Include detection logic
5. Document the vulnerability

### Testing

Before submitting:
- Test with Python 3.7+
- Ensure no syntax errors
- Verify functionality works as expected
- Test edge cases

## Areas for Contribution

We welcome contributions in:

### High Priority
- Additional CVE vulnerability checks
- Support for more manufacturers
- ONVIF protocol implementation
- SSL/TLS security testing
- Firmware version detection

### Medium Priority
- Web UI development
- Additional report formats (PDF, HTML)
- Database integration for results
- Multi-threaded scanning improvements
- Authentication mechanism testing

### Documentation
- Usage examples
- Video tutorials
- Translation to other languages
- Security best practices updates

## Vulnerability Disclosure

If you discover a security vulnerability in the tool:
1. **Do NOT** open a public issue
2. Email the maintainers privately
3. Include detailed information about the vulnerability
4. Allow time for a fix before public disclosure

## Questions?

Feel free to open an issue for:
- Questions about the codebase
- Help with development setup
- Clarification on contribution process

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

Thank you for helping make CyberVisionVAPT better!
