import argparse
from defaults import kdf_iters


def get_parser():
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt data with AES."
    )
    parser.add_argument(
        "-e", "--encrypt", action="store_true", help="Encrypt the input data."
    )
    parser.add_argument(
        "-d", "--decrypt", action="store_true", help="Decrypt the input data."
    )
    parser.add_argument(
        "-a", "--armor", action="store_true", help="Armorize the output (base64)."
    )
    parser.add_argument(
        "-x", "--stdin", action="store_true", help="Read input data from stdin."
    )
    parser.add_argument(
        "-i", "--input", type=str, help="Input data (plaintext or ciphertext)."
    )
    parser.add_argument(
        "-o", "--output", type=str, help="Output file to write the result."
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=kdf_iters,
        help="Set the number of iterations for KDF (default: 99999).",
    )
    return parser
