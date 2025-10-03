import argparse
import asyncio
from .engine import Scanner
from .models import Target
from .reporting import to_console, to_json


def main():
    parser = argparse.ArgumentParser(description="Deep site vulnerability scanner")
    parser.add_argument("url", help="Start URL to scan")
    parser.add_argument("--max-pages", type=int, default=200, dest="max_pages")
    parser.add_argument("--subdomains", action="store_true", dest="subdomains", help="Include subdomains")
    parser.add_argument("--json", action="store_true", dest="as_json", help="Output JSON report")
    parser.add_argument("--no-active", action="store_true", dest="no_active", help="Disable active checks")
    args = parser.parse_args()

    target = Target(start_url=args.url, include_subdomains=args.subdomains, max_pages=args.max_pages)
    scanner = Scanner(target)
    result = asyncio.run(scanner.run(enable_active=not args.no_active))
    if args.as_json:
        print(to_json(result))
    else:
        print(to_console(result))


if __name__ == "__main__":
    main()
