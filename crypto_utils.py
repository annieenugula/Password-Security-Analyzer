"""
crypto_utils.py
=============================================================================
Cryptographic Utility Module for Password Security Analyzer
Academic Project: B.Tech Computer Science (Cyber Security)
=============================================================================
This module provides cryptographic hashing, key derivation, and diffusion
analysis functions using Python standard library packages (hashlib, secrets, hmac).

Core Security Principles Demonstrated:
1. Determinism: Identical inputs always produce identical SHA-256 digests.
2. Pre-image Resistance: One-way trapdoor function; computationally infeasible
   to invert H(m) -> m.
3. Strict Avalanche Criterion (SAC): A single bit change in the input flips
   approximately 50% of the output bits unpredictably.
4. Salting & Key Stretching: PBKDF2-HMAC-SHA-256 applies a cryptographically
   random unique nonce and thousands of iterative HMAC transformations to thwart
   Rainbow Tables and GPU-accelerated brute-force attacks.
5. Constant-Time Verification: hmac.compare_digest prevents side-channel timing attacks.
"""

import hashlib
import secrets
import hmac
from typing import Dict, Any, Tuple


DEFAULT_PBKDF2_ITERATIONS = 100000
HASH_ALGORITHM = 'PBKDF2-HMAC-SHA-256'


def generate_salt(num_bytes: int = 16) -> str:
    """
    Generate a cryptographically secure random salt.
    
    Uses Python's `secrets` module which accesses the operating system's
    CSPRNG (/dev/urandom on Unix/macOS or CryptGenRandom on Windows).
    
    Args:
        num_bytes (int): Number of random bytes (default 16 bytes = 128 bits).
        
    Returns:
        str: Hexadecimal representation of the random salt (32 hex characters).
    """
    return secrets.token_hex(num_bytes)


def compute_sha256(text: str) -> Dict[str, Any]:
    """
    Compute the standard SHA-256 cryptographic hash of a text string.
    
    SHA-256 maps an arbitrary byte sequence to a fixed 256-bit (32-byte) digest,
    typically represented as 64 hexadecimal characters.
    
    IMPORTANT EDUCATIONAL NOTE:
    Hashing is NOT encryption. Encryption is a two-way function requiring a key
    to decrypt back to plaintext. Hashing is strictly a one-way lossy compression
    algorithm designed to be mathematically irreversible.
    
    Args:
        text (str): Input text string.
        
    Returns:
        dict: Hash metadata including hex digest, bit length, and character length.
    """
    encoded_bytes = text.encode('utf-8')
    digest_bytes = hashlib.sha256(encoded_bytes).digest()
    hex_digest = hashlib.sha256(encoded_bytes).hexdigest()
    
    # Convert digest to full 256-bit binary string
    binary_string = ''.join(f'{byte:08b}' for byte in digest_bytes)
    
    return {
        'algorithm': 'SHA-256',
        'input': text,
        'input_length': len(text),
        'hex_digest': hex_digest,
        'char_length': len(hex_digest),  # 64 hex characters
        'bit_length': len(binary_string), # 256 bits
        'binary_digest': binary_string
    }


def compute_avalanche(input1: str, input2: str) -> Dict[str, Any]:
    """
    Demonstrate the Cryptographic Avalanche Effect between two inputs.
    
    The Strict Avalanche Criterion (SAC) states that if a single bit of the input
    is complemented, each of the output bits should change with a probability of 0.5 (50%).
    
    Args:
        input1 (str): First test string (e.g. 'Password123')
        input2 (str): Second test string with minimal difference (e.g. 'Password124')
        
    Returns:
        dict: Detailed bitwise and character difference metrics.
    """
    res1 = compute_sha256(input1)
    res2 = compute_sha256(input2)
    
    bin1 = res1['binary_digest']
    bin2 = res2['binary_digest']
    
    hex1 = res1['hex_digest']
    hex2 = res2['hex_digest']
    
    # Calculate bit-by-bit differences
    total_bits = 256
    diff_bits = sum(1 for b1, b2 in zip(bin1, bin2) if b1 != b2)
    avalanche_percentage = round((diff_bits / total_bits) * 100, 2)
    
    # Calculate hex character differences
    total_hex_chars = 64
    diff_hex_chars = sum(1 for h1, h2 in zip(hex1, hex2) if h1 != h2)
    
    # Generate bit-level status array for frontend matrix rendering
    # Each entry: {'index': i, 'bit1': b1, 'bit2': b2, 'flipped': True/False}
    bit_matrix = []
    for i in range(total_bits):
        bit_matrix.append({
            'index': i,
            'bit1': bin1[i],
            'bit2': bin2[i],
            'flipped': bin1[i] != bin2[i]
        })
        
    # Generate character diff stream
    char_diff1 = []
    char_diff2 = []
    for i in range(total_hex_chars):
        is_diff = hex1[i] != hex2[i]
        char_diff1.append({'char': hex1[i], 'diff': is_diff})
        char_diff2.append({'char': hex2[i], 'diff': is_diff})
        
    # Evaluate quality of diffusion against ideal 50%
    if 45.0 <= avalanche_percentage <= 55.0:
        quality_rating = "Optimal (Strict Avalanche Criterion Satisfied)"
        quality_badge = "success"
    elif 38.0 <= avalanche_percentage <= 62.0:
        quality_rating = "Good Diffusion"
        quality_badge = "info"
    else:
        quality_rating = "Marginal Diffusion"
        quality_badge = "warning"
        
    return {
        'input1': input1,
        'input2': input2,
        'hash1': hex1,
        'hash2': hex2,
        'total_bits': total_bits,
        'diff_bits': diff_bits,
        'identical_bits': total_bits - diff_bits,
        'avalanche_percentage': avalanche_percentage,
        'diff_hex_chars': diff_hex_chars,
        'total_hex_chars': total_hex_chars,
        'quality_rating': quality_rating,
        'quality_badge': quality_badge,
        'bit_matrix': bit_matrix,
        'char_diff1': char_diff1,
        'char_diff2': char_diff2
    }


def derive_pbkdf2_hash(password: str, salt: str, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> str:
    """
    Derive a secure password hash using PBKDF2-HMAC-SHA-256.
    
    Password-Based Key Derivation Function 2 (PBKDF2) applies a pseudorandom function
    (HMAC-SHA-256) to the input password along with a salt value and repeats the process
    many thousands of times (work factor / iterations) to produce a derived key.
    
    Why PBKDF2 is secure for passwords while raw SHA-256 is insecure:
    - Raw SHA-256 can be computed at over 100,000,000,000 hashes per second on a modern GPU rig.
    - PBKDF2 with 100,000+ iterations forces the attacker to execute 100,000 HMAC rounds
      per guess, reducing brute-force throughput by a factor of 100,000x.
      
    Args:
        password (str): Plaintext password to hash.
        salt (str): Cryptographic salt (hexadecimal string).
        iterations (int): Iteration count (work factor). Default 100,000.
        
    Returns:
        str: Hexadecimal derived password hash (64 hex characters = 256 bits).
    """
    password_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    
    derived_key = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password_bytes,
        salt=salt_bytes,
        iterations=iterations,
        dklen=32  # 32 bytes = 256 bits
    )
    return derived_key.hex()


def verify_pbkdf2_password(password: str, stored_salt: str, stored_hash: str, iterations: int = DEFAULT_PBKDF2_ITERATIONS) -> bool:
    """
    Verify a candidate password against a stored PBKDF2-HMAC-SHA-256 hash.
    
    CRITICAL SECURITY PRACTICE:
    Uses `hmac.compare_digest` to perform a CONSTANT-TIME comparison.
    Standard string equality (`==`) terminates early upon encountering the first differing
    character, introducing measurable timing leaks that can allow an attacker to
    reconstruct the hash character-by-character. `hmac.compare_digest` always executes
    in uniform time regardless of character matches.
    
    Args:
        password (str): Candidate plaintext password submitted by the user.
        stored_salt (str): Unique salt retrieved from the database.
        stored_hash (str): Expected hash retrieved from the database.
        iterations (int): Stored iteration work factor.
        
    Returns:
        bool: True if candidate matches the stored digest; False otherwise.
    """
    if not password or not stored_salt or not stored_hash:
        return False
        
    # Re-derive the hash using the identical salt and iteration parameters
    candidate_hash = derive_pbkdf2_hash(password, stored_salt, iterations)
    
    # Perform constant-time verification
    return hmac.compare_digest(candidate_hash, stored_hash)
