import hashlib
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

# ==========================
# Global variables
# ==========================
private_key = None
public_key = None
vehicles = {}  # { number_plate: {"owner": ..., "model": ...} }


# ==========================
# SHA-256 Hashing
# ==========================
def sha256_hash():
    message = input("\nEnter the message to hash: ").strip()
    if not message:
        print("Message cannot be empty.")
        return

    digest = hashlib.sha256(message.encode("utf-8")).hexdigest()
    print(f"SHA-256 hash of the message:\n{digest}\n")


# ==========================
# Digital Signature Functions
# ==========================
def generate_key_pair():
    global private_key, public_key

    print("\nGenerating RSA public–private key pair...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    print("Key pair generated successfully!")
    print("Note: Keys are stored in memory for this session only.\n")


def sign_message():
    global private_key, public_key

    if private_key is None or public_key is None:
        print("\nNo key pair found. Please generate a key pair first (option 2).\n")
        return

    message = input("\nEnter the message to sign: ").strip()
    if not message:
        print("Message cannot be empty.")
        return

    message_bytes = message.encode("utf-8")

    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Encode signature to base64 so that user can easily copy-paste
    signature_b64 = base64.b64encode(signature).decode("utf-8")
    print("\nDigital Signature (Base64 encoded):")
    print(signature_b64)
    print()


def verify_signature():
    global public_key

    if public_key is None:
        print("\nNo public key found. Please generate a key pair first (option 2).\n")
        return

    message = input("\nEnter the original message: ").strip()
    if not message:
        print("Message cannot be empty.")
        return

    signature_b64 = input("Enter the Base64-encoded signature: ").strip()
    if not signature_b64:
        print("Signature cannot be empty.")
        return

    try:
        signature = base64.b64decode(signature_b64.encode("utf-8"))
    except Exception:
        print("Invalid Base64 signature format.")
        return

    message_bytes = message.encode("utf-8")

    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("\nSignature is VALID.\n")
    except InvalidSignature:
        print("\nSignature is INVALID.\n")
    except Exception as e:
        print(f"\nAn error occurred while verifying signature: {e}\n")


# ==========================
# Vehicle Registration System
# ==========================
def register_vehicle():
    print("\n--- Register Vehicle ---")
    number_plate = input("Enter vehicle number plate: ").strip().upper()

    if not number_plate:
        print("Number plate cannot be empty.")
        return

    if number_plate in vehicles:
        print("Error: A vehicle with this number plate is already registered (no duplicates allowed).")
        return

    owner = input("Enter owner name: ").strip()
    if not owner:
        print("Owner name cannot be empty.")
        return

    model = input("Enter vehicle model: ").strip()
    if not model:
        print("Vehicle model cannot be empty.")
        return

    vehicles[number_plate] = {
        "owner": owner,
        "model": model
    }

    print(f"Vehicle with number plate {number_plate} registered successfully.\n")


def retrieve_vehicle():
    print("\n--- Retrieve Vehicle ---")
    number_plate = input("Enter vehicle number plate: ").strip().upper()

    if not number_plate:
        print("Number plate cannot be empty.")
        return

    if number_plate not in vehicles:
        print("No vehicle found with this number plate.\n")
        return

    details = vehicles[number_plate]
    print(f"\nDetails for {number_plate}:")
    print(f"Owner : {details['owner']}")
    print(f"Model : {details['model']}\n")


# ==========================
# Menu
# ==========================
def print_menu():
    print("============================================")
    print("  Cryptography & Blockchain Fundamentals")
    print("============================================")
    print("1. Generate SHA-256 hash of a message")
    print("2. Generate public–private key pair")
    print("3. Sign a message (Digital Signature)")
    print("4. Verify a digital signature")
    print("5. Register a vehicle")
    print("6. Retrieve vehicle details by number plate")
    print("7. Exit")
    print("============================================")


def main():
    while True:
        print_menu()
        choice = input("Enter your choice (1-7): ").strip()

        if choice == "1":
            sha256_hash()
        elif choice == "2":
            generate_key_pair()
        elif choice == "3":
            sign_message()
        elif choice == "4":
            verify_signature()
        elif choice == "5":
            register_vehicle()
        elif choice == "6":
            retrieve_vehicle()
        elif choice == "7":
            print("\nExiting program. Goodbye!")
            break
        else:
            print("\nInvalid choice. Please enter a number between 1 and 7.\n")


if __name__ == "__main__":
    main()
