from __future__ import annotations

import io
import unittest

from sklab import banner
from sklab.output import Output


class BannerTests(unittest.TestCase):
    def render(self, **overrides) -> str:
        values = {
            "modules": {"core": 6, "advanced": 7},
            "target": "k3: windbg-mcp K3 Managed VTL1",
            "drivers": {"h3probe": "stopped"},
            "tagline": banner.TAGLINES[0],
        }
        values.update(overrides)
        return banner.render(**values)

    def test_banner_is_ascii_and_fits_a_terminal(self) -> None:
        text = self.render()
        text.encode("ascii")
        self.assertLessEqual(max(len(line) for line in text.splitlines()), 80)

    def test_banner_reports_target_modules_and_driver_state(self) -> None:
        text = self.render()
        self.assertIn("6 core | 7 advanced modules", text)
        self.assertIn("target k3: windbg-mcp K3 Managed VTL1", text)
        self.assertIn("h3probe stopped", text)
        self.assertIn(banner.TAGLINES[0], text)

    def test_banner_without_a_target_says_so(self) -> None:
        self.assertIn("no target configured", self.render(target=None, drivers={}))

    def test_color_only_when_the_output_can_render_it(self) -> None:
        plain = Output(stream=io.StringIO())
        self.assertNotIn("\x1b[", self.render(paint=plain.paint))
        colored = Output(stream=io.StringIO())
        colored.color = True
        self.assertIn("\x1b[", self.render(paint=colored.paint))


if __name__ == "__main__":
    unittest.main()
