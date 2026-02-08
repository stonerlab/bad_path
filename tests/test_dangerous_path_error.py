"""Tests for DangerousPathError exception."""

import pytest

from bad_path import DangerousPathError


def test_is_exception():
    """Test that DangerousPathError is an Exception."""
    assert issubclass(DangerousPathError, Exception)


def test_can_be_raised():
    """Test that DangerousPathError can be raised."""
    with pytest.raises(DangerousPathError):
        raise DangerousPathError("Test error")


def test_error_message():
    """Test that DangerousPathError carries a message."""
    message = "Test error message"
    with pytest.raises(DangerousPathError) as exc_info:
        raise DangerousPathError(message)
    assert str(exc_info.value) == message


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--pdb"])
