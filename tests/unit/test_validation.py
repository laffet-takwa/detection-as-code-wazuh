"""Unit tests for validation module."""

from pathlib import Path

import pytest
from sentinelforge.validation import validate_yaml_file, validate_yaml_text


class TestYamlValidator:
    """Tests for YAML validation."""

    def test_valid_yaml(self):
        """Test valid YAML parsing."""
        yaml_text = """
title: "Test Rule"
id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
status: stable
description: "This is a test rule description that is long enough."
author: "Test Author"
date: "2024-01-15"
logsource:
  product: linux
  service: sshd
detection:
  selection:
    type: "authentication_failure"
  condition: selection
falsepositives:
  - "Legitimate failed login"
level: medium
"""
        result = validate_yaml_text(yaml_text, "test.yml")
        assert result.ok
        assert result.data is not None
        assert result.data["title"] == "Test Rule"

    def test_empty_file(self):
        """Test empty file rejection."""
        result = validate_yaml_text("", "test.yml")
        assert not result.ok
        assert any(i.code == "yaml.empty_file" for i in result.issues)

    def test_invalid_yaml(self):
        """Test invalid YAML rejection."""
        result = validate_yaml_text("invalid: [", "test.yml")
        assert not result.ok
        assert any(i.code == "yaml.parse_error" for i in result.issues)

    def test_multiple_documents(self):
        """Test multiple YAML documents rejection."""
        yaml_text = """
title: "Rule 1"
id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
---
title: "Rule 2"
id: "b2c3d4e5-f6a7-8901-bcde-f23456789012"
"""
        result = validate_yaml_text(yaml_text, "test.yml")
        assert not result.ok
        assert any(i.code == "yaml.multiple_documents" for i in result.issues)

    def test_non_mapping_top_level(self):
        """Test non-mapping top-level structure rejection."""
        result = validate_yaml_text("- item1\n- item2", "test.yml")
        assert not result.ok
        assert any(i.code == "yaml.invalid_structure" for i in result.issues)

    def test_duplicate_keys(self):
        """Test duplicate key rejection."""
        yaml_text = """
title: "Rule 1"
title: "Rule 2"
id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
"""
        result = validate_yaml_text(yaml_text, "test.yml")
        assert not result.ok
        # Duplicate key detection may vary by YAML parser

    def test_file_not_found(self):
        """Test file not found error."""
        result = validate_yaml_file(Path("/nonexistent/file.yml"), "missing.yml")
        assert not result.ok
        assert any(i.code == "yaml.file_not_found" for i in result.issues)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
