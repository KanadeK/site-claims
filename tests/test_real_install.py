"""A real pip install/check/uninstall reproduction, entirely in temporary storage."""

import unittest

from examples.demo import demo


class RealInstallTests(unittest.TestCase):
    def test_real_environment_collision_then_uninstall_damage(self):
        result = demo()
        self.assertIn("No broken requirements found", result["pip_check"])
        self.assertEqual(result["expected"], "different")
        self.assertEqual(result["after_real_uninstall"], "missing")
        self.assertTrue(result["target_cleaned"])


if __name__ == "__main__":
    unittest.main()
