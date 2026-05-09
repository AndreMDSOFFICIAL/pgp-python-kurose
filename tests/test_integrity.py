from main import *
import os

print("\n========== TESTE DE INTEGRIDADE ==========\n")

try:

    generate_keys("teste_alice")
    generate_keys("teste_bob")

    alice_private = load_private_key("keys/teste_alice_private.pem")
    alice_public = load_public_key("keys/teste_alice_public.pem")

    bob_private = load_private_key("keys/teste_bob_private.pem")
    bob_public = load_public_key("keys/teste_bob_public.pem")

    mensagem = b"Mensagem original"

    assinatura = sign_message(mensagem, alice_private)

    session_key = os.urandom(32)
    iv = os.urandom(16)

    mensagem_cifrada = encrypt_message(
        mensagem,
        session_key,
        iv
    )

    chave_cifrada = encrypt_session_key(
        session_key,
        bob_public
    )

    chave_decifrada = decrypt_session_key(
        chave_cifrada,
        bob_private
    )

    mensagem_decifrada = decrypt_message(
        mensagem_cifrada,
        chave_decifrada,
        iv
    )

    valido = verify_signature(
        mensagem_decifrada,
        assinatura,
        alice_public
    )

    if valido:
        print("[✔] TESTE DE SUCESSO")
        print("Mensagem íntegra e autêntica.")

    else:
        print("[X] Falha na assinatura.")

except Exception as e:
    print(f"[ERRO] {e}")
