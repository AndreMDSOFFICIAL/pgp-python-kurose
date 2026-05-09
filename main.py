import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.exceptions import InvalidSignature

def generate_keys(user):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key = private_key.public_key()

    os.makedirs("keys", exist_ok=True)

    with open(f"keys/{user}_private.pem", "wb") as private_file:
        private_file.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )

    with open(f"keys/{user}_public.pem", "wb") as public_file:
        public_file.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        )

    print(f"[+] Chaves geradas para {user}")


def load_private_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )


def load_public_key(path):
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(
            key_file.read()
        )


def sign_message(message, private_key):
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return True

    except InvalidSignature:
        return False


def encrypt_message(message, session_key, iv):

    padder = sym_padding.PKCS7(128).padder()
    padded_data = padder.update(message) + padder.finalize()

    cipher = Cipher(
        algorithms.AES(session_key),
        modes.CBC(iv)
    )

    encryptor = cipher.encryptor()

    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted


def decrypt_message(ciphertext, session_key, iv):

    cipher = Cipher(
        algorithms.AES(session_key),
        modes.CBC(iv)
    )

    decryptor = cipher.decryptor()

    padded_message = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = sym_padding.PKCS7(128).unpadder()

    message = unpadder.update(padded_message) + unpadder.finalize()

    return message


def encrypt_session_key(session_key, public_key):

    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key


def decrypt_session_key(encrypted_session_key, private_key):

    session_key = private_key.decrypt(
        encrypted_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return session_key


def main():

    print("\\n========== PGP PYTHON - KUROSE ==========\\n")

    generate_keys("alice")
    generate_keys("bob")

    alice_private = load_private_key("keys/alice_private.pem")
    alice_public = load_public_key("keys/alice_public.pem")

    bob_private = load_private_key("keys/bob_private.pem")
    bob_public = load_public_key("keys/bob_public.pem")

    original_message = b"Mensagem ultra secreta enviada por Alice para Bob"

    print(f"[Mensagem Original]")
    print(original_message.decode())

    signature = sign_message(original_message, alice_private)

    print("\\n[+] Mensagem assinada digitalmente.")

    session_key = os.urandom(32)
    iv = os.urandom(16)

    encrypted_message = encrypt_message(
        original_message,
        session_key,
        iv
    )

    print("[+] Mensagem criptografada com AES.")

    encrypted_session_key = encrypt_session_key(
        session_key,
        bob_public
    )

    print("[+] Chave de sessão protegida com RSA.")

    print("\\n========== RECEBIMENTO ==========\\n")

    decrypted_session_key = decrypt_session_key(
        encrypted_session_key,
        bob_private
    )

    decrypted_message = decrypt_message(
        encrypted_message,
        decrypted_session_key,
        iv
    )

    print("[Mensagem Recebida]")
    print(decrypted_message.decode())

    valid = verify_signature(
        decrypted_message,
        signature,
        alice_public
    )

    if valid:
        print("\\n[✔] Assinatura válida.")
        print("[✔] Integridade garantida.")
        print("[✔] Autenticidade confirmada.")

    else:
        print("\\n[X] Assinatura inválida.")
        print("[X] A mensagem foi alterada.")


if __name__ == "__main__":
    main()
