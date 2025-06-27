from pathlib import Path

from bgpsimulator.shared import Settings
from bgpsimulator.simulation_framework import (
    ScenarioConfig,
    Simulation,
    SubprefixHijack,
)


def main():
    """Runs the defaults"""

    sim = Simulation(
        percent_ases_randomly_adopting=(
            10,
            20,
            50,
            80,
            99,
        ),
        scenario_configs=(
            ScenarioConfig(
                label="Subprefix Hijack; ROV Adopting",
                ScenarioCls=SubprefixHijack,
                default_adoption_settings={
                    Settings.ROV: True,
                },
            ),
        ),
        output_dir=Path("~/Desktop/sims/main_ex").expanduser(),
    )
    sim.run()


if __name__ == "__main__":
    main()
