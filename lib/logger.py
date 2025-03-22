import logging
from rich.logging import RichHandler
from rich.console import Console
import os

console = Console()

FORMAT = "%(message)s"

OBJ_EXTRA_FMT = {
    "markup": True,
    "highlighter": False
}

logger = logging.getLogger(__name__)
logger.propagate = False


def init_logger(verbose):
    richHandler = RichHandler(omit_repeated_times=False, 
                              show_path=False, 
                              keywords=[], 
                              console=console)
    
    if verbose:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)


    richHandler.setFormatter(logging.Formatter(FORMAT, datefmt='[%X]'))
    logger.addHandler(richHandler)

