import argparse
import sys


class ArgumentParser(argparse.ArgumentParser):
    """
    This class overwrites the `error` function from the ArgumentParser library in order
    to show the help page in case no argument is supplied by the user.
    """
    def error(self, message) -> None:
        sys.stderr.write(f"[!] Error: {message}\n")
        self.print_help()
        sys.exit(2)