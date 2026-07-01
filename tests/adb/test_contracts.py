import unittest

from pydantic import ValidationError

from volte_mutation_fuzzer.adb.contracts import (
    AdbCollectorConfig,
    AdbDeviceInfo,
    AdbSnapshotResult,
)


class AdbDeviceInfoTests(unittest.TestCase):
    def test_defaults(self) -> None:
        info = AdbDeviceInfo(serial="emulator-5554", state="device")
        self.assertIsNone(info.model)
        self.assertIsNone(info.error)

    def test_extra_forbidden(self) -> None:
        with self.assertRaises(ValidationError):
            AdbDeviceInfo.model_validate(
                {"serial": "emu", "state": "device", "extra_field": True}
            )


class AdbCollectorConfigTests(unittest.TestCase):
    def test_defaults(self) -> None:
        config = AdbCollectorConfig()
        self.assertIsNone(config.serial)
        self.assertEqual(config.buffers, ("main", "system", "radio", "crash"))
        self.assertEqual(config.log_format, "time")

    def test_extra_forbidden(self) -> None:
        with self.assertRaises(ValidationError):
            AdbCollectorConfig.model_validate({"unknown": "value"})


class AdbSnapshotResultTests(unittest.TestCase):
    def test_defaults(self) -> None:
        result = AdbSnapshotResult()
        self.assertIsNone(result.meminfo_path)
        self.assertIsNone(result.dmesg_path)
        self.assertIsNone(result.bugreport_path)
        self.assertEqual(result.errors, ())
