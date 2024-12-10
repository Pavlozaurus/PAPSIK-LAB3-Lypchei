import os
import socket
import ssl
import threading
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


# Перевірка створення тестового файлу
def test_file_access():
    try:
        with open("test_file.txt", "w") as f:
            f.write("Test file created successfully.\n")
        print("Тестовий файл успішно створено.")
    except Exception as e:
        print(f"Помилка створення тестового файлу: {e}")


# Створення CA
def create_ca():
    print("Створення CA...")
    try:
        key = ec.generate_private_key(ec.SECP256R1())
        public_key = key.public_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "My CA"),
        ])
        cert = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(subject) \
            .public_key(public_key) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc)) \
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)) \
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True
            ) \
            .add_extension(
                x509.KeyUsage(digital_signature=False, content_commitment=False,
                              key_encipherment=False, data_encipherment=False,
                              key_agreement=False, key_cert_sign=True,
                              crl_sign=True, encipher_only=False, decipher_only=False),
                critical=True
            ) \
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False
            ) \
            .sign(private_key=key, algorithm=hashes.SHA256())

        with open("ca_key.pem", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("ca_cert.pem", "wb") as f:
            f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

        print("CA сертифікат створено успішно.")
        return key, cert
    except Exception as e:
        print(f"Помилка створення CA: {e}")
        raise


# Функція для створення сертифіката сервера
def create_cert(cert_name, ca_key, ca_cert):
    try:
        print(f"Створення сертифіката для {cert_name}...")
        key = ec.generate_private_key(ec.SECP256R1())
        public_key = key.public_key()

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cert_name),
        ])
        cert = x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(ca_cert.subject) \
            .public_key(public_key) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.now(datetime.timezone.utc)) \
            .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)) \
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("localhost")]),
                critical=False
            ) \
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False
            ) \
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
                critical=False
            ) \
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False
            ) \
            .sign(private_key=ca_key, algorithm=hashes.SHA256())

        with open(f"{cert_name}_key.pem", "wb") as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))

        with open(f"{cert_name}_cert.pem", "wb") as f:
            f.write(cert.public_bytes(encoding=serialization.Encoding.PEM))

        print(f"Сертифікат і ключ для {cert_name} створено.")
    except Exception as e:
        print(f"Помилка створення сертифіката {cert_name}: {e}")
        raise


# Функція запуску сервера
def run_server():
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile="server_cert.pem", keyfile="server_key.pem")

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
            sock.bind(("localhost", 65432))
            sock.listen(1)
            with context.wrap_socket(sock, server_side=True) as ssock:
                print("Сервер очікує підключення...")
                conn, addr = ssock.accept()
                with conn:
                    print(f"Клієнт підключено: {addr}")
                    data = conn.recv(1024)
                    print(f"Отримано: {data.decode()}")
    except Exception as e:
        print(f"Помилка в сервері: {e}")
        raise


# Функція запуску клієнта
def run_client():
    try:
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        context.load_verify_locations("ca_cert.pem")

        with socket.create_connection(("localhost", 65432)) as sock:
            with context.wrap_socket(sock, server_hostname="localhost") as ssock:
                print("Клієнт підключається до сервера...")
                ssock.sendall(b"Hello, server!")
    except Exception as e:
        print(f"Помилка в клієнті: {e}")
        raise


# Основна функція
def main():
    test_file_access()

    # Створення CA
    ca_key, ca_cert = create_ca()

    # Створення сертифіката для сервера
    create_cert("server", ca_key, ca_cert)

    # Запуск сервера і клієнта
    threading.Thread(target=run_server, daemon=True).start()
    run_client()


if __name__ == "__main__":
    main()