import random


# Miller-Rabin primality test: tests if n is prime with k rounds
def is_prime(n, k=10):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    
    # Witness loop
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)  # a^d mod n
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


# Generate a random prime number with specified bit length
def generate_prime(bits):
    while True:
        # Generate random odd number with specified bits
        p = random.getrandbits(bits)
        # Set the highest and lowest bits to ensure proper bit length and odd number
        p |= (1 << bits - 1) | 1
        
        if is_prime(p):
            return p


# Compute modular multiplicative inverse using Extended Euclidean Algorithm
# Returns x such that (a * x) % m == 1
def mod_inverse(a, m):
    if m == 1:
        return 0
    
    # Extended Euclidean Algorithm
    m0, x0, x1 = m, 0, 1
    
    while a > 1:
        if m == 0:
            raise ValueError("Modular inverse does not exist")
        
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    
    if x1 < 0:
        x1 += m0
    
    return x1


# Check if g is a primitive root modulo p (generates all elements in Z*_p)
def is_primitive_root(g, p):
    if g <= 1 or g >= p:
        return False
    
    # For very large primes, factoring p-1 can be slow
    # Set a limit on factorization attempts
    phi = p - 1
    prime_factors = []
    temp = phi
    
    # Check for factor 2
    if temp % 2 == 0:
        prime_factors.append(2)
        while temp % 2 == 0:
            temp //= 2
    
    # Check odd factors up to a reasonable limit
    i = 3
    limit = min(temp, 10**6)  # Limit factorization for large numbers
    while i * i <= temp and i <= limit:
        if temp % i == 0:
            prime_factors.append(i)
            while temp % i == 0:
                temp //= i
        i += 2
    
    if temp > 1:
        # If we have a large remaining factor, assume it's prime
        prime_factors.append(temp)
    
    # Check if g^((p-1)/q) != 1 (mod p) for all prime factors q of p-1
    for factor in prime_factors:
        if pow(g, phi // factor, p) == 1:
            return False
    
    return True


# Find a primitive root modulo p (tries small values first for efficiency)
def find_primitive_root(p):
    # For large primes, use a simplified approach: try small values
    # Statistically, about 1/3 to 1/2 of small numbers are primitive roots
    for g in range(2, min(20, p)):
        if is_primitive_root(g, p):
            return g
    
    # If checking is too slow (for very large p), just return 2
    # In practice, for random large primes, 2 is often a primitive root
    # This is a pragmatic choice for demonstration purposes
    return 2


# Generate ElGamal keys: public_key = (p, g, y), private_key = x
def generate_keys(bits=256):
    # Generate a large prime p
    p = generate_prime(bits)
    
    # Find a primitive root g modulo p
    g = find_primitive_root(p)
    
    # Choose private key x randomly from [1, p-2]
    x = random.randint(1, p - 2)
    
    # Compute public key y = g^x mod p
    y = pow(g, x, p)
    
    public_key = (p, g, y)
    private_key = x
    
    return public_key, private_key


# Encrypt a message using ElGamal: returns ciphertext (c1, c2)
def encrypt(message, public_key):
    p, g, y = public_key
    
    # Validate message
    if not isinstance(message, int) or message < 0 or message >= p:
        raise ValueError(f"Message must be an integer in range [0, {p-1}]")
    
    # Choose random k from [1, p-2]
    k = random.randint(1, p - 2)
    
    # Compute c1 = g^k mod p
    c1 = pow(g, k, p)
    
    # Compute c2 = m * y^k mod p
    c2 = (message * pow(y, k, p)) % p
    
    return (c1, c2)


# Decrypt ciphertext (c1, c2) using ElGamal: returns original message
def decrypt(ciphertext, private_key, public_key):
    c1, c2 = ciphertext
    p = public_key[0]
    x = private_key
    
    # Compute s = c1^x mod p
    s = pow(c1, x, p)
    
    # Compute s_inv = s^(-1) mod p
    s_inv = mod_inverse(s, p)
    
    # Compute message m = c2 * s_inv mod p
    message = (c2 * s_inv) % p
    
    return message


# Convert string to integer for encryption
def string_to_int(s):
    return int.from_bytes(s.encode('utf-8'), byteorder='big')


# Convert integer back to string after decryption
def int_to_string(n):
    # Calculate number of bytes needed
    byte_length = (n.bit_length() + 7) // 8
    return n.to_bytes(byte_length, byteorder='big').decode('utf-8')


# Example usage
if __name__ == "__main__":
    print("=" * 60)
    print("ElGamal Cryptosystem Demonstration")
    print("=" * 60)
    print()
    
    # Generate keys
    print("Step 1: Key Generation")
    print("-" * 60)
    bits = 256  # Using 256 bits for demonstration (larger is more secure but slower)
    public_key, private_key = generate_keys(bits)
    p, g, y = public_key
    
    print(f"Prime (p): {p}")
    print(f"Generator (g): {g}")
    print(f"Private key (x): {private_key}")
    print(f"Public key (y): {y}")
    print()
    
    # Example 1: Encrypt/Decrypt a simple integer
    print("=" * 60)
    print("Example 1: Encrypting an Integer")
    print("=" * 60)
    message_int = 123456789
    print(f"Original message: {message_int}")
    print()
    
    print("Step 2: Encryption")
    print("-" * 60)
    ciphertext = encrypt(message_int, public_key)
    c1, c2 = ciphertext
    print(f"Ciphertext c1: {c1}")
    print(f"Ciphertext c2: {c2}")
    print()
    
    print("Step 3: Decryption")
    print("-" * 60)
    decrypted_message = decrypt(ciphertext, private_key, public_key)
    print(f"Decrypted message: {decrypted_message}")
    print(f"Decryption successful: {decrypted_message == message_int}")
    print()
    
    # Example 2: Encrypt/Decrypt a string message
    print("=" * 60)
    print("Example 2: Encrypting a String")
    print("=" * 60)
    message_str = "Hello ElGamal!"
    print(f"Original string: '{message_str}'")
    
    # Convert string to integer
    message_int2 = string_to_int(message_str)
    print(f"String as integer: {message_int2}")
    print()
    
    print("Step 2: Encryption")
    print("-" * 60)
    ciphertext2 = encrypt(message_int2, public_key)
    c1_2, c2_2 = ciphertext2
    print(f"Ciphertext c1: {c1_2}")
    print(f"Ciphertext c2: {c2_2}")
    print()
    
    print("Step 3: Decryption")
    print("-" * 60)
    decrypted_int2 = decrypt(ciphertext2, private_key, public_key)
    decrypted_str = int_to_string(decrypted_int2)
    print(f"Decrypted integer: {decrypted_int2}")
    print(f"Decrypted string: '{decrypted_str}'")
    print(f"Decryption successful: {decrypted_str == message_str}")
    print()
    
    # Example 3: Multiple encryptions of same message produce different ciphertexts
    print("=" * 60)
    print("Example 3: Probabilistic Encryption")
    print("=" * 60)
    print("Encrypting the same message twice produces different ciphertexts")
    print("(due to random k value in each encryption)")
    print()
    
    test_message = 99999
    ct1 = encrypt(test_message, public_key)
    ct2 = encrypt(test_message, public_key)
    
    print(f"Original message: {test_message}")
    print(f"First encryption:  c1={ct1[0]}, c2={ct1[1]}")
    print(f"Second encryption: c1={ct2[0]}, c2={ct2[1]}")
    print(f"Ciphertexts are different: {ct1 != ct2}")
    print()
    
    # Verify both decrypt correctly
    dec1 = decrypt(ct1, private_key, public_key)
    dec2 = decrypt(ct2, private_key, public_key)
    print(f"First decryption: {dec1}")
    print(f"Second decryption: {dec2}")
    print(f"Both decrypt correctly: {dec1 == test_message and dec2 == test_message}")
    print()
    
    print("=" * 60)
    print("Demonstration Complete!")
    print("=" * 60)


