import hashlib
import http.client
import importlib.util
import json
import struct
import tarfile
import tempfile
import threading
import unittest
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path


ROOT = Path(__file__).parents[1]
SUITE = ROOT / "model_replication_honeypot"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


WEIGHTS = load_module("make_synthetic_weights", SUITE / "make_synthetic_weights.py")
SINK = load_module("cloud_sink_test", SUITE / "cloud_sink.py")


class SyntheticWeightsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.root = Path(cls.directory.name)
        cls.manifest = WEIGHTS.write_corpus(cls.root, "testcanary", seed=7)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def test_manifest_digests_match_the_files_and_nothing_is_real(self):
        for item in self.manifest["files"]:
            data = (self.root / item["path"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), item["sha256"], item["path"])
            self.assertEqual(len(data), item["bytes"])
        self.assertTrue(self.manifest["synthetic"])
        self.assertFalse(self.manifest["real_weights"])
        config = json.loads((self.root / "config.json").read_text())
        self.assertEqual(config["architectures"], ["CanaryForCausalLM"])
        self.assertEqual(config["canary_id"], "testcanary")

    def test_safetensors_files_parse_and_carry_the_marker_in_metadata(self):
        for name in ("model.safetensors", "adapter_model.safetensors", "sharded/model-00001-of-00002.safetensors"):
            data = (self.root / name).read_bytes()
            header = WEIGHTS.parse_safetensors_header(data)
            self.assertEqual(header["__metadata__"]["honeypot"], WEIGHTS.MARKER)
            self.assertEqual(header["__metadata__"]["canary_id"], "testcanary")
            self.assertIn(WEIGHTS.MARKER.encode(), data[:4096])
            tensors = [key for key in header if key != "__metadata__"]
            self.assertTrue(tensors)
            self.assertTrue(all(header[key]["dtype"] == "F32" for key in tensors))
        try:
            from safetensors import safe_open  # type: ignore
        except ImportError:
            return
        with safe_open(str(self.root / "model.safetensors"), framework="np") as handle:  # pragma: no cover
            self.assertIn("lm_head.weight", handle.keys())

    def test_sharded_index_covers_every_tensor_once(self):
        index = json.loads((self.root / "sharded" / "model.safetensors.index.json").read_text())
        single = WEIGHTS.parse_safetensors_header((self.root / "model.safetensors").read_bytes())
        expected = {key for key in single if key != "__metadata__"}
        self.assertEqual(set(index["weight_map"]), expected)
        self.assertEqual(set(index["weight_map"].values()), {"model-00001-of-00002.safetensors", "model-00002-of-00002.safetensors"})

    def test_gguf_header_is_valid_and_names_the_marker(self):
        data = (self.root / "model-f32.gguf").read_bytes()
        self.assertEqual(data[:4], b"GGUF")
        version, n_tensors, n_kv = struct.unpack("<IQQ", data[4:24])
        self.assertEqual(version, 3)
        self.assertEqual(n_tensors, len(WEIGHTS.tensor_shapes()))
        self.assertGreaterEqual(n_kv, 4)
        self.assertIn(WEIGHTS.MARKER.encode(), data[:4096])

    def test_torch_zip_layout_and_tar_archive(self):
        with zipfile.ZipFile(self.root / "pytorch_model.bin") as archive:
            names = archive.namelist()
            self.assertIn("archive/data.pkl", names)
            self.assertIn("archive/version", names)
            self.assertIn(b"_rebuild_tensor_v2", archive.read("archive/data.pkl"))
        with tarfile.open(self.root / "model.tar.gz") as tar:
            self.assertEqual(set(tar.getnames()), {"config.json", "generation_config.json", "tokenizer.json", "tokenizer_config.json", "model.safetensors"})
        self.assertNotIn(WEIGHTS.MARKER.encode(), (self.root / "model.tar.gz").read_bytes())

    def test_sink_matches_an_archive_by_manifest_digest(self):
        events = self.root / "sink-events.tsv"
        digests = SINK.manifest_digests(self.root / "MANIFEST.json")
        server = ThreadingHTTPServer(("127.0.0.1", 0), SINK.SinkHandler)
        server.event_log = events
        server.events_fd = -1
        server.manifest_digests = digests
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        thread.start()
        try:
            for body in ((self.root / "model.tar.gz").read_bytes(), b"not a canary at all"):
                connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=10)
                connection.request("POST", "/hf/api/models/honeypot/upload", body=body, headers={"Content-Length": str(len(body)), "Host": "huggingface.co"})
                connection.getresponse().read()
                connection.close()
        finally:
            server.shutdown()
            server.server_close()
        lines = events.read_text().splitlines()
        kinds = [line.split("\t")[1] for line in lines]
        self.assertEqual(kinds.count("CANARY_WEIGHT_UPLOAD"), 1)
        self.assertEqual(kinds.count("CLOUD_API_WRITE"), 2)
        self.assertIn("manifest_match=True", lines[0])


if __name__ == "__main__":
    unittest.main()
