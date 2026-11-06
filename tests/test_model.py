"""Автотесты модели распространения вирусов.

Запуск:  python -m unittest discover -s tests -v
"""
import unittest

from virus_lab import build_network, make_simulation, normalize, run
from virus_lab.network import DEFAULT_NETWORK, TOPOLOGIES
from virus_lab.rng import Rng
from virus_lab.simulation import Simulation
from virus_lab.viruses import VIRUSES, get_virus
from virus_lab import theory


class RngTest(unittest.TestCase):
    def test_deterministic(self):
        a = [Rng(123).random() for _ in range(5)]
        b = [Rng(123).random() for _ in range(5)]
        self.assertEqual(a, b)

    def test_range(self):
        r = Rng(7)
        for _ in range(1000):
            x = r.random()
            self.assertGreaterEqual(x, 0.0)
            self.assertLess(x, 1.0)

    def test_matches_known_mulberry32(self):
        # Канонические первые значения алгоритма mulberry32 для seed=0
        # (широко документированы; совпадение с JS-движком проверяет web/test.html).
        r = Rng(0)
        vals = [round(r.random(), 10) for _ in range(3)]
        self.assertEqual(vals, [0.2664292087, 0.0003297457, 0.2232720274])


class NetworkTest(unittest.TestCase):
    def test_sizes(self):
        for topo in TOPOLOGIES:
            net = build_network({"topology": topo}, seed=1)
            self.assertEqual(net.size, 100)
            self.assertGreater(net.edge_count(), 0, topo)

    def test_reproducible(self):
        a = build_network({"topology": "corporate"}, seed=42)
        b = build_network({"topology": "corporate"}, seed=42)
        self.assertEqual([h.os for h in a.hosts], [h.os for h in b.hosts])
        self.assertEqual(a.neighbors, b.neighbors)

    def test_custom_size(self):
        net = build_network({"hosts": 300, "subnets": 10}, seed=1)
        self.assertEqual(net.size, 300)
        self.assertEqual(len(net.subnet_names()), 10)

    def test_legacy_never_patched(self):
        net = build_network({"patch_coverage": 1.0}, seed=5)
        for h in net.hosts:
            if h.legacy:
                self.assertFalse(h.patched)

    def test_offline_hosts_have_no_links(self):
        net = build_network({"offline_share": 0.5}, seed=3)
        offline = [h for h in net.hosts if h.offline]
        self.assertTrue(offline)
        for h in offline:
            self.assertEqual(net.degree(h.id), 0)

    def test_rejects_bad_size(self):
        with self.assertRaises(ValueError):
            build_network({"hosts": 2}, seed=1)
        with self.assertRaises(ValueError):
            build_network({"hosts": 10, "subnets": 9}, seed=1)


class VirusTest(unittest.TestCase):
    def test_all_presets_valid(self):
        for vid in VIRUSES:
            v = get_virus(vid)
            self.assertIn("beta", v)
            self.assertIn("p2p_contacts", v)
            self.assertTrue(v["targets"])

    def test_override(self):
        v = get_virus({"base": "worm_smb", "beta": 0.9})
        self.assertEqual(v["beta"], 0.9)
        self.assertEqual(v["contacts"], VIRUSES["worm_smb"]["contacts"])


class SimulationTest(unittest.TestCase):
    def test_reproducible(self):
        s1 = run(normalize({"seed": 11}))
        s2 = run(normalize({"seed": 11}))
        self.assertEqual([h["I"] for h in s1.history], [h["I"] for h in s2.history])

    def test_conservation(self):
        # Сумма S+E+I+R всегда равна числу узлов.
        sim = make_simulation(normalize({"seed": 4}))
        for _ in range(50):
            sim.step()
            row = sim.history[-1]
            self.assertEqual(row["S"] + row["E"] + row["I"] + row["R"], sim.n)

    def test_patch_helps_on_average(self):
        def avg(cov):
            xs = [run(normalize({"network": {"patch_coverage": cov}}), seed).summary()["ever_fraction"]
                  for seed in range(25)]
            return sum(xs) / len(xs)
        self.assertGreater(avg(0.0), avg(0.9))

    def test_segmentation_blocks_cross_subnet(self):
        seg = [run(normalize({"params": {"segmentation": True}, "network": {"patch_coverage": 0.3}}), s)
               .summary()["ever_fraction"] for s in range(25)]
        no = [run(normalize({"params": {"segmentation": False}, "network": {"patch_coverage": 0.3}}), s)
              .summary()["ever_fraction"] for s in range(25)]
        self.assertGreater(sum(no) / len(no), sum(seg) / len(seg))

    def test_torrent_reaches_offline(self):
        # Торрент-троян должен уметь заражать ПК вне ЛВС.
        reached = False
        for seed in range(15):
            s = run(normalize({"virus": "torrent_trojan",
                               "network": {"offline_share": 0.3, "p2p_share": 0.5}}), seed)
            if s.summary()["offline"]["infected"] > 0:
                reached = True
                break
        self.assertTrue(reached, "торрент-троян не заразил ни одного офлайн-ПК за 15 прогонов")

    def test_lan_worm_never_spreads_to_offline(self):
        # Обычный сетевой червь не РАСПРОСТРАНЯЕТСЯ на ПК вне ЛВС (у них нет связей).
        # Единственное исключение — если офлайн-ПК сам оказался нулевым пациентом.
        for seed in range(15):
            s = run(normalize({"virus": "worm_smb", "network": {"offline_share": 0.3}}), seed)
            for h in s.hosts:
                if h.offline and s.was_infected[h.id]:
                    self.assertIn(h.id, s.seeds, "офлайн-ПК заразился не будучи нулевым пациентом")

    def test_channels_counted(self):
        s = run(normalize({"virus": "torrent_worm", "model": "SEIR",
                           "network": {"p2p_share": 0.3}}), 5)
        ch = s.summary()["by_channel"]
        self.assertEqual(sum(ch.values()), s.infections)


class TheoryTest(unittest.TestCase):
    def test_r0_positive_for_worm(self):
        sim = make_simulation(normalize({"virus": "worm_smb"}), keep_events=False)
        th = theory.parameters(sim.net, sim.virus, sim.model, sim.params)
        self.assertGreater(th["R0"], 1.0)

    def test_final_size_monotonic(self):
        self.assertEqual(theory.final_size_sir(0.5), 0.0)
        self.assertGreater(theory.final_size_sir(3.0), theory.final_size_sir(1.5))

    def test_mean_field_runs(self):
        sim = make_simulation(normalize({"virus": "torrent_trojan",
                                         "network": {"p2p_share": 0.4}}), keep_events=False)
        curve = theory.mean_field(sim.net, sim.virus, sim.model, sim.params)
        self.assertGreater(len(curve), 1)


if __name__ == "__main__":
    unittest.main()
