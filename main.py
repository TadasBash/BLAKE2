import sys
from blake2 import blake2s

def read_file_bytes(filename):
    with open(filename, 'rb') as f:
        return f.read()

def write_output(filename, hex_hash):
    with open(filename, 'w') as f:
        f.write(hex_hash)

def main():
    if len(sys.argv) < 2:
        print("Naudojimas: python main.py <įvesties_failas> [išvesties_failas]")
        return

    input_file = sys.argv[1]

    try:
        data = read_file_bytes(input_file)
    except FileNotFoundError:
        print(f"Klaida: failas '{input_file}' nerastas.")
        return

    result = blake2s(data)
    hex_result = result.hex().upper()

    if len(sys.argv) == 3:
        output_file = sys.argv[2]
        write_output(output_file, hex_result)
    else:
        print(f"Maišos reikšmė: {hex_result}")

if __name__ == "__main__":
    main()
