import logging
import logging.config

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        }
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "default",
            "level": "INFO",
        },
        "file": {
            "class": "logging.FileHandler",
            "formatter": "default",
            "level": "DEBUG",
            "filename": "server.log",
        }
    },
    "root": {
        "handlers": ["console", "file"],
        "level": "INFO"
    }
}


def module_logger(name: str, silence: bool = False, level: str | int | None = None) -> logging.Logger:
    """
    Return a logger for one module, optionally silenced.
    """
    lg = logging.getLogger(name) # get the logger by name
    if isinstance(level, str):
        level = getattr(logging, level.upper(), logging.INFO)
    if level is not None:
        lg.setLevel(level) # set the level
    if silence:
        lg.disabled = True # turn off the logger
        lg.propagate = False # stop sending to the root
        if not lg.handlers:
            lg.addHandler(logging.NullHandler()) # removing nohandler error
    return lg # return the logger


def setup_logging():
    """
    logging with the configuration
    """
    logging.config.dictConfig(LOGGING_CONFIG)
