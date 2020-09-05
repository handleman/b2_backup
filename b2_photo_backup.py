import argparse
from pprint import pprint


def init_argparse() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="make copy of your files to given B2 folder")
    parser.add_argument(
        "-v", "--version", action="version",
        version=f"{parser.prog} version 1.0.0"
    )
    parser.add_argument(
        "-f", "--folder", help="Path to folder you want to upload to B2 cloud"
    )
    parser.add_argument(
        "-b", "--bucket-name", help="B2 Cloud bucket name to which you want to copy files"
    )
    return parser


def main() -> None:
    parser = init_argparse()
    args = vars(parser.parse_args())

    pprint(args)


if __name__ == "__main__":
    main()
