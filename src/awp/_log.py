"""Logging: the package logs through the "awp" logger."""

import logging

logger = logging.getLogger("awp")


def log(msg: str) -> None:
    logger.info(msg)


def debug(msg: str) -> None:
    logger.debug(msg)
