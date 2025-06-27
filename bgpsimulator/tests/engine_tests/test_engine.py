from pathlib import Path

import pytest

from bgpsimulator.engine_runner import EngineRunConfig, EngineRunner

from .engine_test_configs import engine_test_configs


@pytest.mark.engine
class TestEngine:
    """Performs a system test on the engine

    See tutorial for in depth details
    """

    @pytest.mark.parametrize("conf", engine_test_configs)
    def test_engine(self, conf: EngineRunConfig, overwrite: bool, dpi: int | None):
        """Performs a system test on the engine

        See tutorial for in depth details
        """

        EngineRunner(
            base_dir=self.base_dir,
            engine_run_config=conf,
            overwrite=overwrite,
            compare_against_ground_truth=True,
            write_diagrams=True,
        ).run(dpi=dpi)

    @property
    def base_dir(self) -> Path:
        """Returns test output dir"""

        return Path(__file__).parent / "engine_test_outputs"
