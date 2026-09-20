import logging

import pytest

from darnit.core.logging import configure_logging, get_logger


@pytest.mark.unit
class TestGetLogger:
    def test_returns_darnit_logger(self):
        logger = get_logger()
        assert logger.name == "darnit"

    def test_returns_child_logger(self):
        logger = get_logger("sieve")
        assert logger.name == "darnit.sieve"

    def test_has_null_handler_by_default(self):
        logger = get_logger()
        assert any(isinstance(h, logging.NullHandler) for h in logger.handlers)


@pytest.mark.unit
class TestConfigureLogging:
    def test_sets_log_level(self):
        configure_logging("DEBUG")
        logger = get_logger()
        assert logger.level == logging.DEBUG

    def test_adds_stream_handler(self):
        configure_logging()
        logger = get_logger()
        assert any(isinstance(h, logging.StreamHandler) for h in logger.handlers)

    def test_no_duplicate_handlers_on_repeated_calls(self):
        # Call twice, should not double handlers
        configure_logging()
        configure_logging()
        logger = get_logger()
        stream_handlers = [h for h in logger.handlers if isinstance(h, logging.StreamHandler)]
        assert len(stream_handlers) <= 1
