import argparse
import sys

from . import __version__
from .core import GatewayError, dependencies


def main():
    parser = argparse.ArgumentParser(description="Publish a local proxy over a private VPN client.")
    parser.add_argument("--version", action="version", version=f"VPN Dock {__version__}")
    parser.add_argument("--check-runtime", action="store_true", help="check host dependencies")
    args = parser.parse_args()
    try:
        from .ui import Application
        if args.check_runtime:
            dependencies()
            print(f"VPN Dock {__version__} · GTK and network dependencies available")
            return 0
        application = Application()
    except (GatewayError, ImportError, ValueError) as error:
        print(f"VPN Dock: {error}", file=sys.stderr)
        return 1
    return application.run([])


if __name__ == "__main__":
    raise SystemExit(main())
