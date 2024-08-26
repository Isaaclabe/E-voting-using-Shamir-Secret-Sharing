import random
from sympy import mod_inverse

def generate_random_coefficients(encoded_vote, threshold, prime):
    """
    Generates random coefficients for a polynomial used in Shamir's Secret Sharing scheme.

    Args:
        encoded_vote (int): The constant term of the polynomial, representing the encoded vote.
        threshold (int): The minimum number of shares required to reconstruct the secret.
        prime (int): A large prime number used for modulo operations.

    Returns:
        list: A list of random coefficients for the polynomial.
    """
    coefficients = [encoded_vote]  # The constant term (secret) of the polynomial
    for _ in range(threshold - 1):
        coefficients.append(random.randint(1, prime - 1))
    return coefficients

def evaluate_polynomial_at(x, coefficients, prime):
    """
    Evaluates a polynomial at a given point x using modular arithmetic.

    Args:
        x (int): The point at which to evaluate the polynomial.
        coefficients (list): The coefficients of the polynomial.
        prime (int): A large prime number used for modulo operations.

    Returns:
        int: The result of the polynomial evaluated at point x (mod prime).
    """
    result = 0
    for i, coeff in enumerate(coefficients):
        result += coeff * (x ** i)
        result %= prime
    return result

def reconstruct_secret(shares, prime):
    """
    Reconstructs the secret from a list of shares using Lagrange interpolation.

    Args:
        shares (list of tuples): A list of tuples, where each tuple contains (x_i, y_i), representing the shares.
        prime (int): A large prime number used for modulo operations.

    Returns:
        int: The reconstructed secret.
    """
    total_sum = 0
    k = len(shares)
    for i in range(k):
        x_i, y_i = shares[i]
        product = y_i
        for j in range(k):
            if i != j:
                x_j, _ = shares[j]
                product *= x_j * mod_inverse(x_j - x_i, prime) % prime
                product %= prime
        total_sum += product
        total_sum %= prime
    return total_sum
