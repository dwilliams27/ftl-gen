"""Text transformation utilities for chaos mode.

These are FREE local transforms that don't require LLM calls.
"""

from random import Random


class TextTransformer:
    """Applies chaos transformations to text."""

    # Character substitutions (leetspeak-ish)
    SUBSTITUTIONS = {
        "a": ["4", "@"],
        "e": ["3"],
        "i": ["1", "!"],
        "o": ["0"],
        "s": ["5", "$"],
        "t": ["7"],
        "l": ["1"],
        "b": ["8"],
        "g": ["9"],
    }

    # Zalgo combining characters (above)
    ZALGO_ABOVE = [
        "\u0300",  # Combining Grave Accent
        "\u0301",  # Combining Acute Accent
        "\u0302",  # Combining Circumflex
        "\u0303",  # Combining Tilde
        "\u0304",  # Combining Macron
        "\u0305",  # Combining Overline
        "\u0306",  # Combining Breve
        "\u0307",  # Combining Dot Above
        "\u0308",  # Combining Diaeresis
        "\u030a",  # Combining Ring Above
        "\u030b",  # Combining Double Acute
        "\u030c",  # Combining Caron
        "\u030f",  # Combining Double Grave
        "\u0311",  # Combining Inverted Breve
    ]

    # Zalgo combining characters (below)
    ZALGO_BELOW = [
        "\u0316",  # Combining Grave Below
        "\u0317",  # Combining Acute Below
        "\u0318",  # Combining Left Tack Below
        "\u0319",  # Combining Right Tack Below
        "\u031c",  # Combining Left Half Ring Below
        "\u031d",  # Combining Up Tack Below
        "\u031e",  # Combining Down Tack Below
        "\u031f",  # Combining Plus Sign Below
        "\u0320",  # Combining Minus Sign Below
        "\u0324",  # Combining Diaeresis Below
        "\u0325",  # Combining Ring Below
        "\u0326",  # Combining Comma Below
        "\u0329",  # Combining Vertical Line Below
    ]

    def __init__(self, chaos_level: float, seed: int | None = None):
        """Initialize transformer.

        Args:
            chaos_level: 0.0 to 1.0 chaos intensity
            seed: Random seed for reproducibility
        """
        self.chaos_level = max(0.0, min(1.0, chaos_level))
        self.rng = Random(seed)

    def transform_title(self, text: str) -> str:
        """Transform a weapon/item title.

        At low chaos: Minor changes
        At high chaos: More dramatic changes
        """
        if self.chaos_level < 0.1:
            return text

        result = []
        for char in text:
            # Character substitution chance scales with chaos
            if (
                char.lower() in self.SUBSTITUTIONS
                and self.rng.random() < self.chaos_level * 0.3
            ):
                subs = self.SUBSTITUTIONS[char.lower()]
                result.append(self.rng.choice(subs))
            # Random capitalization at high chaos
            elif self.rng.random() < self.chaos_level * 0.2:
                result.append(char.swapcase())
            else:
                result.append(char)

        return "".join(result)

    def transform_description(self, text: str) -> str:
        """Transform a description text.

        Applies various text warping effects based on chaos level.
        """
        if self.chaos_level < 0.1:
            return text

        # Word shuffling within sentences (at high chaos)
        if self.chaos_level > 0.5 and self.rng.random() < self.chaos_level * 0.3:
            text = self._shuffle_words(text)

        # Character transforms
        if self.chaos_level > 0.3:
            text = self._apply_char_transforms(text)

        # Zalgo text at very high chaos
        if self.chaos_level > 0.8 and self.rng.random() < (self.chaos_level - 0.8) * 2:
            text = self._apply_zalgo(text)

        return text

    def _shuffle_words(self, text: str) -> str:
        """Shuffle words within sentences while preserving punctuation."""
        sentences = text.split(". ")
        result = []

        for sentence in sentences:
            words = sentence.split()
            if len(words) > 3:
                # Keep first and last word, shuffle middle
                middle = words[1:-1]
                self.rng.shuffle(middle)
                words = [words[0]] + middle + [words[-1]]
            result.append(" ".join(words))

        return ". ".join(result)

    def _apply_char_transforms(self, text: str) -> str:
        """Apply character-level transforms."""
        result = []
        for char in text:
            # Substitution
            if (
                char.lower() in self.SUBSTITUTIONS
                and self.rng.random() < self.chaos_level * 0.15
            ):
                subs = self.SUBSTITUTIONS[char.lower()]
                result.append(self.rng.choice(subs))
            # Random caps
            elif char.isalpha() and self.rng.random() < self.chaos_level * 0.1:
                result.append(char.swapcase())
            else:
                result.append(char)

        return "".join(result)

    def _apply_zalgo(self, text: str) -> str:
        """Apply zalgo combining characters for glitchy effect."""
        result = []
        for char in text:
            result.append(char)
            if char.isalpha() and self.rng.random() < 0.3:
                # Add 1-3 combining characters
                count = self.rng.randint(1, 3)
                for _ in range(count):
                    if self.rng.random() < 0.5:
                        result.append(self.rng.choice(self.ZALGO_ABOVE))
                    else:
                        result.append(self.rng.choice(self.ZALGO_BELOW))

        return "".join(result)

    def maybe_transform_title(self, text: str) -> str:
        """Transform title only if chaos roll succeeds."""
        if self.rng.random() < self.chaos_level * 0.5:
            return self.transform_title(text)
        return text

    def maybe_transform_description(self, text: str) -> str:
        """Transform description only if chaos roll succeeds."""
        if self.rng.random() < self.chaos_level * 0.4:
            return self.transform_description(text)
        return text
