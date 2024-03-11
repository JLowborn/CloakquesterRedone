from colorama import Fore, Style, init


def color_print(text, color="white", end="\n"):
    """
    Print text with Colorama styling based on the specified color.

    Args:
        text (str): The text to print.
        color (str): The color to apply. Accepted values: "black", "red", "green",
            "yellow", "blue", "magenta", "cyan", "white", "reset" (to reset to default color).
        end (str, optional): The string appended after the text. Defaults to "\n".
    """
    colors = {
        "black": Fore.BLACK,
        "red": Fore.RED,
        "green": Fore.GREEN,
        "yellow": Fore.YELLOW,
        "blue": Fore.BLUE,
        "magenta": Fore.MAGENTA,
        "cyan": Fore.CYAN,
        "white": Fore.WHITE,
        "reset": Style.RESET_ALL
    }

    init()

    styled_text = f"{colors.get(color.lower(), '')}{text}{Style.RESET_ALL}"
    print(styled_text, end=end)
