from cryptography.fernet import Fernet
import os

class PasswordManager:
    def __init__(self, master_password, data_file='passwords.dat'):
        self.master_password = master_password.encode()
        self.data_file = data_file
        self.key = None

    def generate_key(self):
        salt = os.urandom(16)
        kdf = Fernet.generate_key()
        self.key = Fernet(kdf)

    def encrypt(self, data):
        return self.key.encrypt(data)

    def decrypt(self, encrypted_data):
        return self.key.decrypt(encrypted_data)

    def load_data(self):
        if not os.path.exists(self.data_file):
            self.generate_key()
            return {}

        with open(self.data_file, 'rb') as file:
            data = file.read()

        if data:
            self.key = Fernet(data[:44])  # Extract key from the first 44 bytes
            encrypted_passwords = data[44:]
            decrypted_data = self.decrypt(encrypted_passwords)
            return eval(decrypted_data)  # Insecure; only for basic example

        return {}

    def save_data(self, data):
        with open(self.data_file, 'wb') as file:
            encrypted_data = self.key.encrypt(str(data).encode())
            file.write(self.key._encryption_key + encrypted_data)  # Insecure; only for basic example

    def get_password(self, service):
        data = self.load_data()
        return data.get(service, None)

    def set_password(self, service, password):
        data = self.load_data()
        data[service] = password
        self.save_data(data)

if __name__ == "__main__":
    master_password = input("Enter your master password: ")
    password_manager = PasswordManager(master_password)

    while True:
        print("\nOptions:")
        print("1. Get password")
        print("2. Set password")
        print("3. Exit")

        choice = input("Choose an option (1/2/3): ")

        if choice == "1":
            service = input("Enter the service for which you want the password: ")
            password = password_manager.get_password(service)
            if password:
                print(f"Password for {service}: {password}")
            else:
                print(f"No password found for {service}")
        elif choice == "2":
            service = input("Enter the service: ")
            password = input("Enter the password: ")
            password_manager.set_password(service, password)
            print("Password set successfully!")
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")
