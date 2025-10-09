"""Test EngineRunConfig JSON serialization and deserialization"""

import json
from pathlib import Path

import pytest

from bgpsimulator.engine_runner import EngineRunConfig
from bgpsimulator.tests.engine_tests.engine_test_configs.examples.ex_config_000 import (
    ex_config_000,
)


class TestEngineRunConfig:
    """Tests for EngineRunConfig JSON roundtrip"""

    def test_json_roundtrip(self, tmp_path: Path):
        """Test that a config can be saved and loaded back identically"""

        config1 = ex_config_000

        # Convert to JSON and back
        json_str = json.dumps(config1.to_json(), indent=2)

        # Save to temporary file
        json_file_1 = tmp_path / "test_config_1.json"
        json_file_1.write_text(json_str)

        # Load it back
        json_obj = json.loads(json_str)
        json_obj["prevent_naming_duplicates"] = False  # Disable duplicate check
        config2 = EngineRunConfig.from_json(json_obj)

        # Convert config2 back to JSON
        json_str2 = json.dumps(config2.to_json(), indent=2)
        json_file_2 = tmp_path / "test_config_2.json"
        json_file_2.write_text(json_str2)

        # Parse both JSON strings for comparison
        json_obj_1 = json.loads(json_str)
        json_obj_2 = json.loads(json_str2)

        # The only difference should be prevent_naming_duplicates
        assert json_obj_1.get("prevent_naming_duplicates") == True
        assert json_obj_2.get("prevent_naming_duplicates") == False

        # Remove prevent_naming_duplicates for comparison
        json_obj_1.pop("prevent_naming_duplicates", None)
        json_obj_2.pop("prevent_naming_duplicates", None)

        # Now they should be identical
        assert json_obj_1 == json_obj_2

        # Config objects should be equal
        assert config1 == config2
        assert config1.scenario_config == config2.scenario_config
        assert config1.as_graph == config2.as_graph

    def test_propagation_rank_asns_preserved(self, tmp_path: Path):
        """Test that propagation_rank_asns is preserved during serialization"""

        config1 = ex_config_000

        # Convert to JSON
        json_obj = config1.to_json()

        # Check that propagation_rank_asns is present and not empty
        assert "as_graph" in json_obj
        assert "propagation_rank_asns" in json_obj["as_graph"]
        propagation_ranks = json_obj["as_graph"]["propagation_rank_asns"]
        assert len(propagation_ranks) > 0
        assert all(isinstance(rank, list) for rank in propagation_ranks)

        # Deserialize
        json_obj["prevent_naming_duplicates"] = False
        config2 = EngineRunConfig.from_json(json_obj)

        # Convert back to JSON
        json_obj2 = config2.to_json()

        # propagation_rank_asns should be preserved
        assert (
            json_obj["as_graph"]["propagation_rank_asns"]
            == json_obj2["as_graph"]["propagation_rank_asns"]
        )
