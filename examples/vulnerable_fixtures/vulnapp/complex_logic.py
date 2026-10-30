"""INTENTIONALLY COMPLEX FIXTURE: cyclomatic complexity far above rank C."""


def classify(a: int, b: int, c: int, d: int, mode: str) -> str:  # noqa: C901
    result = ""
    for i in range(a):
        if i % 2 == 0 and b > 0:
            result += "a"
        elif i % 3 == 0 or c > 1:
            result += "b"
        elif i % 5 == 0 and d < 0:
            result += "c"
        if mode == "x":
            result += "x"
        elif mode == "y":
            result += "y"
        elif mode == "z":
            result += "z"
        elif mode == "w":
            result += "w"
        if a > 10 and b > 10:
            result += "big"
        elif a > 5 or b > 5:
            result += "mid"
        while d > 0 and c > 0:
            d -= 1
            if d % 2:
                result += "o"
            elif d % 3:
                result += "t"
        try:
            result += str(10 // (c - i))
        except ZeroDivisionError:
            result += "z"
        except ValueError:
            result += "v"
    return result or ("empty" if a == 0 else "none")
