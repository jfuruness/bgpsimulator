"""Shares chache dir, logger"""

import logging
from datetime import date
from pathlib import Path

from platformdirs import PlatformDirs, PlatformDirsABC

#############
# Cache Dir #
#############

# NOTE: Can't use getpass here due to windows bug (https://bugs.python.org/issue32731)
DIRS: PlatformDirsABC = PlatformDirs("bgpsimulator", Path.home().name)

SINGLE_DAY_CACHE_DIR: Path = Path(DIRS.user_cache_dir) / str(date.today())
SINGLE_DAY_CACHE_DIR.mkdir(exist_ok=True, parents=True)

##########
# Logger #
##########

bgpsimulator_logger = logging.getLogger("bgpsimulator")
bgpsimulator_logger.setLevel(logging.INFO)

# Add StreamHandler to output logs to console
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)

# Optional: Add a formatter for better readability
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
stream_handler.setFormatter(formatter)

# Attach handler to the logger
bgpsimulator_logger.addHandler(stream_handler)
