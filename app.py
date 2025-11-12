from __future__ import annotations

import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
SRC_PATH = PROJECT_ROOT / "src"

if str(PROJECT_ROOT) not in sys.path:  # pragma: no cover - environment dependent
    sys.path.append(str(PROJECT_ROOT))
if str(SRC_PATH) not in sys.path:  # pragma: no cover
    sys.path.append(str(SRC_PATH))

from src.ui.app import main  # noqa: E402  pylint: disable=wrong-import-position


if __name__ == "__main__":
    main()

