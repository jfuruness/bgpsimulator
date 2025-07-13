import warnings
from collections import deque

from bgpsimulator.as_graphs import AS
from bgpsimulator.route_validator import ROA
from bgpsimulator.shared import (
    CommonPrefixes,
    IPAddr,
    Relationships,
    Settings,
    Timestamps,
    bgpsimulator_logger,
)
from bgpsimulator.simulation_engine import Announcement as Ann
from bgpsimulator.simulation_engine import SimulationEngine
from bgpsimulator.simulation_framework.scenarios.scenario import Scenario


class ShortestPathPrefixHijack(Scenario):
    """Attacker announces the shortest path that bypasses all defenses"""

    required_aspa_attacker_setting = Settings.ORIGIN_PREFIX_HIJACK_CUSTOMERS

    def _get_seed_asn_ann_dict(self, engine: SimulationEngine) -> dict[int, list[Ann]]:
        return {
            **self._get_legitimate_origin_seed_asn_ann_dict(engine),
            **self._get_attacker_seed_asn_ann_dict(engine),
        }

    ###########################
    # Legitimate origin funcs #
    ###########################

    def _get_legitimate_origin_seed_asn_ann_dict(
        self, engine: SimulationEngine
    ) -> dict[int, list[Ann]]:
        anns = dict()
        for legitimate_origin_asn in self.legitimate_origin_asns:
            anns[legitimate_origin_asn] = [
                Ann(
                    prefix=CommonPrefixes.PREFIX.value,
                    as_path=(legitimate_origin_asn,),
                    next_hop_asn=legitimate_origin_asn,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.LEGITIMATE_ORIGIN,
                )
            ]
        return anns

    def _get_roas(
        self,
        *,
        seed_asn_ann_dict: dict[int, list[Ann]],
        engine: SimulationEngine,
    ) -> list[ROA]:
        """Returns a list of ROAs"""

        return [
            ROA(CommonPrefixes.PREFIX.value, x) for x in self.legitimate_origin_asns
        ]

    def _get_dest_ip_addr(self) -> IPAddr:
        """Returns the destination IP address for the scenario"""

        return IPAddr("1.2.3.4")

    ##################
    # Attacker funcs #
    ##################

    def _get_attacker_seed_asn_ann_dict(
        self, engine: SimulationEngine
    ) -> dict[int, list[Ann]]:
        all_used_settings = self.scenario_config.all_used_settings
        # Go strongest to weakest
        if any(setting in all_used_settings for setting in self.bgpisec_settings):
            # See post_propagation_hook - this is where the attack takes place
            # This must happen this way since bgpisec requires an actual ann
            # whereas ASPA just requires a "potential/plausible" ann
            return dict()
        elif any(setting in all_used_settings for setting in self.asra_settings):
            return self._get_aspa_seed_asn_ann_dict(engine)
        elif any(setting in all_used_settings for setting in self.aspa_settings):
            if (
                Settings.ORIGIN_PREFIX_HIJACK_CUSTOMERS
                not in self.scenario_config.attacker_settings
            ):
                raise ValueError(
                    "For a shortest path export all attack against ASPA, "
                    "scenario_config.attacker_settings must be set to  "
                    f"{Settings.ORIGIN_PREFIX_HIJACK_CUSTOMERS}, "
                    "which you can import like "
                    "from bgpsimulator.shared import Settings"
                )
            return self._get_aspa_seed_asn_ann_dict(
                engine, self.required_aspa_attacker_setting
            )
        elif any(setting in all_used_settings for setting in self.path_end_settings):
            return self._get_path_end_seed_asn_ann_dict(engine)
        elif any(setting in all_used_settings for setting in self.rov_settings):
            return self._get_forged_origin_seed_asn_ann_dict(engine)
        elif any(setting in all_used_settings for setting in self.pre_rov_settings):
            return self._get_prefix_attacker_seed_asn_ann_dict(engine)
        else:
            raise NotImplementedError(
                f"Need to code shortest path attack against {all_used_settings}"
            )

    def post_propagation_hook(
        self,
        engine: SimulationEngine,
        percent_ases_randomly_adopting: float,
        trial: int,
        propagation_round: int,
    ) -> None:
        """Performs Shortest path prefix hijack against BGPiSec classes

        For this attack, since bgp-isec transitive attributes are present,
        an actual announcement in a local RIB of an AS must be chosen
        (this assumes the attacker can see any local RIB through looking glass
        servers or route collectors, etc). This is unlike the theoretical shortest
        path like against ASPA (or in other words - when attacking ASPA you
        want the shortest plausible path. When attacking bgpisec you need the
        shortest path that exists).

        To do this, we iterate through all ASes and choose an announcement that
        has the shortest path in a local RIB where the last AS on the path is not
        adopting. Then the attacker appends their ASN and we repropagate.
        We could do this using algorithms and such depending on the class, but
        that can be a future improvement. For now I'm going for accuracy.

        A caveat for selecting the best shortest path - the attacker should always
        prefer announcements which have no OTC attributes over announcements with
        OTC attributes, since the attacker would then be detected less when
        propagating to providers.

        Additionally, much like an AccidentalRouteLeak, previously the attacker would
        simply modify their local RIB and then propagate again. However - this
        has some drawbacks. Then the attacker must deploy BGPFull
        (that uses withdrawals) and the entire graph has to propagate again.
        BGPFull (and subclasses of it) are MUCH slower than BGP due to all the extra
        computations for withdrawals, AdjRIBsIn, AdjRIBsOut, etc. Additionally,
        propagating a second round after the ASGraph is __already__ full
        is wayyy more expensive than propagating when the AS graph is empty.

        Instead, we now get the announcement that the attacker needs to leak
        after the first round of propagating the valid prefix.
        Then we clear the graph, seed those announcements, and propagate again
        This way, we avoid needing BGPFull (since the graph has been cleared,
        there is no need for withdrawals), and we avoid propagating a second
        time after the graph is alrady full.

        Since this simulator treats each propagation round as if it all happens
        at once, this is possible.
        """

        if not any(
            setting in self.scenario_config.all_used_settings
            for setting in self.bgpisec_settings
        ):
            return
        elif propagation_round == 0:
            # Force their to be two rounds of propagation
            # Can't set this in the class var since you only want it to apply here
            if self.scenario_config.propagation_rounds < 2:
                raise ValueError("Please set ScenarioConfig.propagation_rounds to 2")

            seed_asn_ann_dict: dict[int, list[Ann]] = dict()

            # Find the best ann for attacker to fake with
            best_ann: Ann | None = None
            for _asn, as_obj in engine.as_graph.as_dict.items():
                # Search for an AS that doesn't next_hop signature
                if not self.as_is_adopting_bgpisec(as_obj):
                    for ann in as_obj.policy.local_rib.values():
                        if best_ann is None:
                            best_ann = ann
                        # Prefer anns without OTC, always
                        elif ann.only_to_customers and not best_ann.only_to_customers:
                            continue
                        elif not ann.only_to_customers and best_ann.only_to_customers:
                            best_ann = ann
                        # Lastly prefer shorter paths
                        elif len(ann.as_path) < len(best_ann.as_path):
                            best_ann = ann

            if not best_ann:
                # NOTE: may be possible due to the 1% being all disconnected ASes
                # or when valid ann is in one of those disconnected ASes
                # this happens if you run 1k trials
                bgpsimulator_logger.info(
                    f"Couldn't find best_ann at "
                    f"{percent_ases_randomly_adopting}% adoption"
                )
                # When this occurs, use victim's ann to at least do forged-origin
                victim_as_obj = engine.as_graph.as_dict[
                    next(iter(self.legitimate_origin_asns))
                ]
                for ann in victim_as_obj.policy.local_rib.values():
                    best_ann = ann

            assert best_ann, "mypy"
            # Add fake announcements
            assert self.attacker_asns, "You must select at least 1 AS to leak"
            for attacker_asn in self.attacker_asns:
                seed_asn_ann_dict[attacker_asn] = [
                    best_ann.copy(
                        as_path=(attacker_asn, *best_ann.as_path),
                        recv_relationship=Relationships.ORIGIN,
                        timestamp=Timestamps.ATTACKER.value,
                        next_hop_asn=attacker_asn,
                    )
                ]

            # Reset the engine for the next run
            self.seed_asn_ann_dict = seed_asn_ann_dict
            self.setup_engine(engine)
        elif propagation_round > 1:
            raise NotImplementedError(
                "Shortest path prefix hijack is not supported for "
                "multiple propagation rounds with BGPiSec"
            )

    def _get_aspa_seed_asn_ann_dict(
        self,
        engine: SimulationEngine,
        required_attacker_setting: Settings | None = None,
    ) -> dict[int, list[Ann]]:
        """Gets the shortest path undetected by ASPA"""

        if len(self.legitimate_origin_asns) > 1:
            raise NotImplementedError

        if required_attacker_setting is not None:
            self._validate_required_aspa_attacker_setting(required_attacker_setting)

        shortest_valid_path = self._find_shortest_valley_free_non_aspa_adopting_path(
            root_asn=next(iter(self.legitimate_origin_asns)), engine=engine
        )
        seed_asn_ann_dict = dict()
        for attacker_asn in self.attacker_asns:
            # There are cases where the attacker is a part of this
            # We add the attacker later so just remove it here
            current_shortest_valid_path = tuple(
                [x for x in shortest_valid_path if x != attacker_asn]
            )

            seed_asn_ann_dict[attacker_asn] = [
                Ann(
                    prefix=CommonPrefixes.PREFIX.value,
                    as_path=(attacker_asn, *current_shortest_valid_path),
                    next_hop_asn=attacker_asn,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.ATTACKER,
                )
            ]

        return seed_asn_ann_dict

    def _validate_required_aspa_attacker_setting(
        self, required_attacker_setting: Settings
    ) -> None:
        """Validates that the required ASPA attacker setting is used"""

        if required_attacker_setting not in self.scenario_config.attacker_settings:
            raise ValueError(
                "For a shortest path export all attack against ASPA, "
                "scenario_config.attacker_settings must be set to  "
                f"{required_attacker_setting}, which you can import like "
                "from bgpsimulator.shared import Settings"
            )

    def _find_shortest_valley_free_non_aspa_adopting_path(
        self, root_asn: int, engine: SimulationEngine
    ) -> tuple[int, ...]:
        """Finds the shortest non adopting path from the root asn

        Announcements from customers > peers > providers, since
        policies like ASPA and bgp-isec would reject announcements
        that are already going to customers, etc. So even if the path
        is longer, it's better to be accepted by going to a provider
        """

        root_as = engine.as_graph.as_dict[root_asn]

        # {ASN: as_path to get here}
        # NOTE: I used to have AS as the key, but weakref.Proxy isn't hashable
        # https://stackoverflow.com/a/68273386/8903959
        visited = dict()

        # First, use BFS on provider relationships
        queue: deque[tuple[AS, tuple[int, ...]]] = deque([(root_as, (root_as.asn,))])
        while queue:
            as_, as_path = queue.popleft()
            if as_.asn not in visited:
                if not self.as_is_adopting_aspa(as_):
                    return as_path
                visited[as_.asn] = as_path
                for provider_asn in engine.as_graph.as_dict[as_.asn].provider_asns:
                    if provider_asn not in visited:
                        queue.append(
                            (
                                engine.as_graph.as_dict[provider_asn],
                                (provider_asn, *as_path),
                            )
                        )

        # Then, go in order of provider relationships
        # This is a nice optimization, since the dictionary maintains order
        # and BFS increments in order of distance
        for visited_asn, as_path in visited.copy().items():
            visited_as = engine.as_graph.as_dict[visited_asn]
            for peer_as in visited_as.peers:
                if not self.as_is_adopting_aspa(peer_as):
                    return (peer_as.asn, *as_path)
                elif peer_as.asn not in visited:
                    visited[peer_as.asn] = (peer_as.asn, *as_path)

        # At this point, if we still haven't found it, it's a customer
        # relationship (or doesn't exist).
        # From here, the proper way to do things would be to use some modified
        # djikstras algorithm
        # But it's important to note that this is the uncommon case
        # since this would only occur if all of the input clique is adopting.
        # If that were the case, djikstras algorithm would have a very bad runtime
        # since 99% of ASes would be adopting
        # Additionally, this function only runs once per trial
        # for all these reasons, I'm not going to implement a modified djikstras,
        # which may be prone to error, and just do it the naive way, which is much
        # less error prone
        # To do this, I'll  simply iterate through all remaining ASes, and then sort
        # them and return the shortest AS path (or None)

        # BFS code removed here

        # The above commented out implementation basically did BFS using
        # customer relationships from every provider within the provider + peer
        # cone. The problem with that is you end up rechecking the same ASN
        # many different times, and you essentially are doing BFS 1000 times
        # due to the size of the provider + peer cone.
        # The only way to avoid rechecking the ASes, and avoid blowing up the RAM
        # is actually to use propagation ranks, since the graph is essentially ordered
        # As to why it seems to occur so frequently, when the input clique typically
        # should have non adopting ASNs, it's because about .2% of the CAIDA graph
        # gets disconnected. That means 99.8% of the time, a victim can reach the
        # input clique. But .998 ^ 1000 trials means ~13% chance that the victim
        # can reach the input clique every time. That's why we had to fix this,
        # even though in theory the problem should rarely occur.

        # So this is in the end doing something very similar to propagation
        # however, there are a few differences that I think make this worth keeping
        # 1. It's wayyyy faster than copying announcements and function call overhead
        #    especially with non-simple policies
        # 2. We can use this to modify any hijacks (whereas if this used propagation,
        #    it would be it's own scenario class
        # 3. The algo stops when it reaches a non adopting ASN, and the overwhelming
        #    majority of the time, that's going to be in the provider cone of the root
        #    asn, which is usually < 1000 ASes, which is going to be very fast
        # anyways, on with the propagation lol

        non_adopting_customer_asns = set()
        for propagation_rank in reversed(engine.as_graph.propagation_ranks):
            for as_obj in propagation_rank:
                shortest_provider_path: tuple[int, ...] | None = None
                for provider_asn in as_obj.provider_asns:
                    provider_path = visited.get(provider_asn)
                    if provider_path is not None and (
                        shortest_provider_path is None
                        or len(provider_path) < len(shortest_provider_path)
                    ):
                        shortest_provider_path = provider_path
                # relevant to root ASN
                if shortest_provider_path:
                    new_as_path = (as_obj.asn, *shortest_provider_path)
                    old_as_path = visited.get(as_obj.asn)
                    if not old_as_path or len(old_as_path) > len(new_as_path):
                        visited[as_obj.asn] = new_as_path
                    if not self.as_is_adopting_aspa(as_obj):
                        non_adopting_customer_asns.add(as_obj.asn)

        # Sort through non adopting customer ASNs to find shortest path
        if non_adopting_customer_asns:
            non_adopting_customer_paths = {
                asn: visited[asn] for asn in non_adopting_customer_asns
            }
            sorted_non_adopting_customer_paths = sorted(
                non_adopting_customer_paths.items(), key=lambda x: len(x[1])
            )
            best_asn, best_as_path = sorted_non_adopting_customer_paths[0]
            return best_as_path
        else:
            warnings.warn(
                "Shortest path against ASPA is none? "
                "This should only happen at full adoption...",
                stacklevel=2,
            )
            return ()

    def as_is_adopting_aspa(self, as_obj: AS) -> bool:
        """Returns True if the AS is adopting ASPA"""

        return self.as_is_adopting_any_settings(
            as_obj, self.aspa_settings | self.asra_settings
        )

    def as_is_adopting_bgpisec(self, as_obj: AS) -> bool:
        """Returns True if the AS is adopting BGP-I-SEC"""
        return self.as_is_adopting_any_settings(as_obj, self.bgpisec_settings)

    def as_is_adopting_any_settings(self, as_obj: AS, settings: set[Settings]) -> bool:
        """Returns True if the AS is adopting any of the settings

        Unfortunately must operate this way since the engine is not yet set up, so the
        settings are not available to the AS class
        """

        if as_obj.asn in self.attacker_asns and any(
            value
            for setting, value in self.scenario_config.attacker_settings.items()
            if setting in settings
        ):
            return True
        if as_obj.asn in self.legitimate_origin_asns and any(
            value
            for setting, value in (
                self.scenario_config.legitimate_origin_settings.items()
            )
            if setting in settings
        ):
            return True
        if as_obj.asn in self.adopting_asns and any(
            value
            for setting, value in self.scenario_config.override_adoption_settings.get(
                as_obj.asn, {}
            ).items()
            if setting in settings
        ):
            return True
        if as_obj.asn in self.adopting_asns and any(
            value
            for setting, value in self.scenario_config.default_adoption_settings.items()
            if setting in settings
        ):
            return True
        if as_obj.asn not in self.adopting_asns and any(
            value
            for setting, value in self.scenario_config.override_base_settings.get(
                as_obj.asn, {}
            ).items()
            if setting in settings
        ):
            return True
        if as_obj.asn not in self.adopting_asns and any(
            value
            for setting, value in self.scenario_config.default_base_settings.items()
            if setting in settings
        ):
            return True
        return False

    def _get_path_end_seed_asn_ann_dict(
        self, engine: SimulationEngine
    ) -> dict[int, list[Ann]]:
        """Gets the shortest path undetected by Path-End"""

        if len(self.legitimate_origin_asns) > 1:
            raise NotImplementedError

        root_asn = next(iter(self.legitimate_origin_asns))
        root_as_obj = engine.as_graph.as_dict[root_asn]
        shortest_valid_path: tuple[int, ...] = ()
        for first_provider_asn in root_as_obj.provider_asns:
            # You only need legit origin and their provider, you don't need three
            # for secondary_provider in first_provider.providers:
            #     return (secondary_provider.asn, first_provider.asn, root_asn)
            shortest_valid_path = (first_provider_asn, root_asn)
            break

        if not shortest_valid_path:
            # Some ASes don't have providers, and are stubs that are peered
            for first_peer_asn in root_as_obj.peer_asns:
                shortest_valid_path = (first_peer_asn, root_asn)
                break

        if not shortest_valid_path:
            # Strange case but it could happen
            for first_customer_asn in root_as_obj.customer_asns:
                shortest_valid_path = (first_customer_asn, root_asn)
                break

        if shortest_valid_path == ():
            warnings.warn(
                "Shortest path against pathend is none? "
                "This should only happen at full adoption...",
                stacklevel=2,
            )

        seed_asn_ann_dict = dict()
        for attacker_asn in self.attacker_asns:
            seed_asn_ann_dict[attacker_asn] = [
                Ann(
                    prefix=CommonPrefixes.PREFIX.value,
                    as_path=(attacker_asn, *shortest_valid_path),
                    next_hop_asn=attacker_asn,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.ATTACKER,
                )
            ]

        return seed_asn_ann_dict

    def _get_forged_origin_seed_asn_ann_dict(
        self, engine: SimulationEngine
    ) -> dict[int, list[Ann]]:
        """Returns a dict of ASNs to announcements for the forged origin attacker"""

        legitimate_origin_asn = next(iter(self.legitimate_origin_asns))
        seed_asn_ann_dict = dict()
        for attacker_asn in self.attacker_asns:
            seed_asn_ann_dict[attacker_asn] = [
                Ann(
                    prefix=CommonPrefixes.PREFIX.value,
                    as_path=(attacker_asn, legitimate_origin_asn),
                    next_hop_asn=attacker_asn,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.ATTACKER,
                )
            ]

        return seed_asn_ann_dict

    def _get_prefix_attacker_seed_asn_ann_dict(
        self, engine: SimulationEngine
    ) -> dict[int, list[Ann]]:
        """Returns a dict of ASNs to announcements for the prefix attacker"""

        seed_asn_ann_dict = dict()
        for attacker_asn in self.attacker_asns:
            seed_asn_ann_dict[attacker_asn] = [
                Ann(
                    prefix=CommonPrefixes.PREFIX.value,
                    as_path=(attacker_asn,),
                    next_hop_asn=attacker_asn,
                    recv_relationship=Relationships.ORIGIN,
                    timestamp=Timestamps.ATTACKER,
                )
            ]
        return seed_asn_ann_dict

    ##################
    # Setting Groups #
    ##################

    @property
    def bgpisec_settings(self) -> set[Settings]:
        return {Settings.BGP_I_SEC, Settings.BGP_I_SEC_TRANSITIVE}

    @property
    def asra_settings(self) -> set[Settings]:
        return {Settings.ASRA, Settings.ASPA_W_N, Settings.ASPAPP}

    @property
    def aspa_settings(self) -> set[Settings]:
        return {Settings.ASPA}

    @property
    def path_end_settings(self) -> set[Settings]:
        return {Settings.PATH_END}

    @property
    def rov_settings(self) -> set[Settings]:
        return {
            Settings.ROV,
            Settings.ROVPP_V1_LITE,
            Settings.ROVPP_V2_LITE,
            Settings.ROVPP_V2I_LITE,
        }

    @property
    def pre_rov_settings(self) -> set[Settings]:
        return {
            Settings.BGPSEC,
            Settings.PROVIDER_CONE_ID,
            Settings.ONLY_TO_CUSTOMERS,
            Settings.AS_PATH_EDGE_FILTER,
            Settings.ENFORCE_FIRST_AS,
            Settings.PEERLOCK_LITE,
        }
