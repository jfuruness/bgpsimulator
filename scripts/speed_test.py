import cProfile
import io
import pstats
import time
from pathlib import Path

from bgpsimulator.simulation_framework import (
    ScenarioConfig,
    Simulation,
    SubprefixHijack,
)
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
        output_dir=Path("~/Desktop/sims/speed_test").expanduser(),
        num_trials=10,
        parse_cpus=1,
    )
    sim.run(GraphFactoryCls=None)


if __name__ == "__main__":
    start = time.perf_counter()
    profiler = cProfile.Profile()
    profiler.enable()
    main()
    print(f"{time.perf_counter() - start:.2f}s")
    # v9 Normal 61.6s
    # v8 68.53s
    # v9 again only 63.88s
    # CIBUILDWHEEL=1 pip install frozendict - 64s
    # After removing 5% info tag from announcements
    profiler.disable()

    # Create a StringIO object to capture the profiling results
    s = io.StringIO()

    # Create a Stats object with the profiling results
    sortby = "cumtime"
    ps = pstats.Stats(profiler, stream=s).sort_stats(sortby)

    # Print the profiling results to the StringIO object
    ps.print_stats()

    # Write the profiling results to a file
    with open("/home/anon/Desktop/bgpsimulator_profile_output.txt", "w") as f:
        f.write(s.getvalue())
