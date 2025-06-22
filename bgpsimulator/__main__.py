from pathlib import Path

from bgpsimulator.simulation_framework import ScenarioConfig, Simulation, SubprefixHijack
from bgpsimulator.shared import Settings


def main():
    """Runs the defaults"""

    sim = Simulation(
        percent_ases_randomly_adopting=(
            0.1,
            0.2,
            0.5,
            0.8,
            0.99,
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