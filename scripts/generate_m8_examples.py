from pathlib import Path

from sklab.m8_examples import generate


if __name__ == "__main__":
    repository = Path(__file__).resolve().parents[1]
    for path in generate(repository / "examples" / "m8"):
        print(path.relative_to(repository))
