import random
from mutators.base import BaseMutator


class XMLMutator(BaseMutator):
    def mutate(self, base: bytes) -> bytes:
        if self.seed_text is None:
            return self.mutate_bytes(base)
        text = self.seed_text
        variants = []
        variants.append(text.replace("</", "<\/", 1))
        variants.append(text.replace("=\"", "=\"'", 1))
        variants.append("<!--" + (text[:1000]) + "-->")
        variants.append("<root>" + text + "</root>")
        variants.append(text + "\n" + "<a" + ("x" * random.randint(10, 200)) + "/>\n")
        s = random.choice(variants)
        return s.encode('utf-8', errors='ignore')
