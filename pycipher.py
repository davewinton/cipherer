from cipherer import Cipherer
from arghandler import get_parser
from getpass import getpass
from os import path
from sys import stdin, stderr, stdout, exit


def main():
    parser = get_parser()
    args = parser.parse_args()
    cipherer = Cipherer(iterations=args.iterations)
    is_file = False

    # Read input data
    if args.stdin:
        input_data = stdin.read().strip()
    elif args.input:
        if path.isfile(args.input):
            is_file = True
            with open(args.input, "rb" if args.decrypt else "r") as f:
                input_data = f.read()
        else:
            print("[!] Input path is not valid! Exiting..")
            exit(1)
    else:
        parser.error("No input provided. Use --input or --stdin.")

    userpass = getpass("Enter password: ")

    try:
        if args.encrypt:
            confirm_pass = getpass("Confirm password: ")
            if confirm_pass != userpass:
                print("[!] Passwords do not match.. exiting")
                exit(1)
            ciphertext = cipherer.encrypt(input_data, userpass)
            result = cipherer.armorize(
                ciphertext) if args.armor else ciphertext
        elif args.decrypt:
            if args.armor:
                input_data = cipherer.dearmorize(input_data)
            if not is_file:
                result = cipherer.decrypt(
                    input_data.encode() if isinstance(input_data, str) else input_data,
                    userpass,
                )
            else:
                result = cipherer.decrypt(input_data, userpass)
        else:
            parser.error("Specify either --encrypt or --decrypt.")

        if args.output:
            with open(args.output, "wb" if isinstance(result, bytes) else "w") as f:
                f.write(result)
        else:
            print("[!] No output path set, printing output to terminal..")
            print("=== OUTPUT ===")
            stdout.write(result if isinstance(
                result, str) else cipherer.armorize(result))
    except Exception as e:
        print(f"Error: {e}", file=stderr)


if __name__ == "__main__":
    main()
