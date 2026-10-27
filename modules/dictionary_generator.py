from pathlib import Path

LEET = str.maketrans({
    "a": "@",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "$"
})

def generate_dictionary(name="", year="", keyword=""):
    seeds = []
    for value in (name, year, keyword):
        value = value.strip()
        if value:
            seeds.append(value)

    candidates = set()

    for seed in seeds:
        variants = {
            seed,
            seed.lower(),
            seed.upper(),
            seed.capitalize(),
            seed.translate(LEET),
        }
        for v in variants:
            candidates.add(v)
            if year and v != year:
                candidates.add(v + year)
            candidates.add(v + "123")
            candidates.add(v + "!")
            candidates.add(v + "@123")

    # Small educational pattern set; deliberately bounded.
    common = ["password", "welcome", "admin", "qwerty", "letmein"]
    for word in common:
        candidates.update({word, word + "123", word + "!"})

    return sorted(c for c in candidates if c)


def save_wordlist(words, path: Path):
    path.write_text("\n".join(words) + "\n", encoding="utf-8")
