# Pure-Python implementation of the ElGamal digital signature scheme.
# No external cryptographic helpers are used; every arithmetic routine is
# implemented manually with only the modulo operator provided by Python.


def egcd(a: int, b: int):
    # Extended Euclidean algorithm.
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)


def modinv(a: int, modulo: int) -> int:
    # Modular multiplicative inverse.
    g, x, _ = egcd(a % modulo, modulo)
    if g != 1:
        raise ValueError(f"No inverse exists for {a} modulo {modulo}")
    return x % modulo


def modexp(base: int, exponent: int, modulo: int) -> int:
    # Binary modular exponentiation implemented from scratch.
    result = 1
    base = base % modulo
    e = exponent
    while e > 0:
        if e & 1:
            result = (result * base) % modulo
        base = (base * base) % modulo
        e >>= 1
    return result


def gcd(a: int, b: int) -> int:
    # Greatest common divisor.
    while b:
        a, b = b, a % b
    return a


def message_to_int(message: str) -> int:
    # Convert a string message into an integer deterministically by treating
    # UTF-8 bytes as base-256 digits.
    value = 0
    for byte in message.encode("utf-8"):
        value = (value << 8) + byte
    return value


class ElGamalKeys:
    # Lightweight container for key material.
    def __init__(self, prime: int, generator: int, private_key: int, public_key: int):
        self.prime = prime
        self.generator = generator
        self.private_key = private_key
        self.public_key = public_key


class PseudoRandom:
    # Simple linear congruential generator fully implemented with manual math.
    def __init__(self, seed: int = 123456789):
        modulus = 2147483647
        self.modulus = modulus
        self.state = seed % modulus
        if self.state == 0:
            self.state = 1

    def next(self) -> int:
        self.state = (1103515245 * self.state + 12345) % self.modulus
        return self.state

    def rand_between(self, low: int, high: int) -> int:
        if low > high:
            raise ValueError("Low endpoint cannot exceed high endpoint.")
        span = high - low + 1
        return low + (self.next() % span)


class ElGamalSigner:
    # Implements key generation, signing, and verification for ElGamal signatures.

    def __init__(self, prime: int, generator: int, seed: int = 987654321):
        if prime <= 2:
            raise ValueError("Prime modulus must be greater than 2.")
        if not (1 < generator < prime):
            raise ValueError("Generator must be within (1, p).")
        self.p = prime
        self.g = generator
        self.prng = PseudoRandom(seed)

    def keygen(self, private_key: int | None = None) -> ElGamalKeys:
        # Generate a private/public key pair.
        # Private key x is in [2, p-2]; public key y = g^x mod p.
        p_minus_2 = self.p - 2
        if private_key is None:
            private_key = self.prng.rand_between(2, self.p - 1)
        if not (2 <= private_key <= p_minus_2 + 1):
            raise ValueError("Private key must lie in [2, p-1].")
        public_key = modexp(self.g, private_key, self.p)
        return ElGamalKeys(self.p, self.g, private_key, public_key)

    def sign(self, message: str, keys: ElGamalKeys, k: int | None = None):
        # Sign a message string using the private key.
        # k must be randomly chosen in [1, p-2] and gcd(k, p-1) = 1.
        if keys.private_key is None:
            raise ValueError("Private key required for signing.")

        m = message_to_int(message) % (self.p - 1)

        if k is None:
            # Choose k until coprime with p-1.
            while True:
                candidate = self.prng.rand_between(1, self.p - 2)
                if gcd(candidate, self.p - 1) == 1:
                    k = candidate
                    break
        if not (1 <= k <= self.p - 2):
            raise ValueError("k must be in [1, p-2].")
        if gcd(k, self.p - 1) != 1:
            raise ValueError("k must be coprime to p-1.")

        r = modexp(self.g, k, self.p)
        k_inv = modinv(k, self.p - 1)
        s = ((m - keys.private_key * r) * k_inv) % (self.p - 1)
        return (r, s)

    def verify(self, message: str, signature: tuple[int, int], keys: ElGamalKeys) -> bool:
        # Verify a signature using the public key.
        r, s = signature
        if not (0 < r < self.p):
            return False
        if not (0 <= s < self.p - 1):
            return False

        m = message_to_int(message) % (self.p - 1)
        left = (modexp(keys.public_key, r, self.p) * modexp(r, s, self.p)) % self.p
        right = modexp(self.g, m, self.p)
        return left == right


def example_usage():
    # Demonstrates key generation, signing, and verification on a sample message.
    # For real security, use large safe primes and secure generators.
    prime = 30803  # Example 16-bit prime
    generator = 2
    signer = ElGamalSigner(prime, generator)
    keys = signer.keygen()

    message = "ElGamal signatures from scratch!"
    signature = signer.sign(message, keys)
    verified = signer.verify(message, signature, keys)

    print("=== ElGamal Digital Signature Demo ===")
    print(f"Prime (p): {prime}")
    print(f"Generator (g): {generator}")
    print(f"Private key (x): {keys.private_key}")
    print(f"Public key (y): {keys.public_key}")
    print(f"Message: {message}")
    print(f"Signature (r, s): {signature}")
    print(f"Verification result: {verified}")


if __name__ == "__main__":
    example_usage()

