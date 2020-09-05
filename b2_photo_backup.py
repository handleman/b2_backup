import argparse
import os
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
    folder = args["folder"]
    excludes = ['.DS_Store', '.Trashes', '.fseventsd', '.Spotlight-V100']
    files = os.listdir(folder)

    fileswalked = os.walk(folder)

    pprint(args)

    for root, directories, files in os.walk(folder):
        for name in files:
            if name not in excludes:
                pprint(os.path.join(root, name))


if __name__ == "__main__":
    main()
