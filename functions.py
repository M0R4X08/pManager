import os
import json
import base64
import stat
from encryption_utils import EncryptionUtils as eu
from custom_exceptions import CustomExceptions as ce
import getpass
class Functions:


    @classmethod
    def create_directory(cls,directory):
        if not os.path.exists(directory):
            os.makedirs(directory)

    def clear_console():
        os.system('cls' if os.name == 'nt' else 'clear')

    @classmethod
    def restrict_access(cls,file_path):
        os.chmod(file_path, stat.S_IRUSR | stat.S_IWUSR)

    @classmethod
    def restrict_folder_access(cls,folder_path):
        os.chmod(folder_path, stat.S_IRUSR | stat.S_IWUSR)

    @classmethod
    def confirmation_master_password(cls, password_path_key):
        try:  
                print("Insert master password:")
                password_key = input("Password: ")
                if not password_key:
                    raise ce.PasswordEmpty("Password cannot be empty")
                with open(password_path_key, 'rb') as f:
                    password_hash = f.read()
                if not eu.verify_password(password_hash, password_key):
                    raise ce.PasswordIncorrect("Incorrect password")
                return True
        except (ce.PasswordEmpty,ce.PasswordIncorrect) as e:
            print(f"Error: {e}")
            return False

    @classmethod
    def save_password(cls, password_encrypted, file_password):

        password_encrypted_base64 = {}

        for site, credentials_list in password_encrypted.items():
            encrypted_credentials_list = []
            for credentials in credentials_list:
                encrypted_credentials = {}
                for key, value in credentials.items():
                    try:
                    
                        if isinstance(value, bytes):
                            # Codificar en base64 solo si el valor es de tipo bytes
                            encrypted_credentials[key] = base64.b64encode(value).decode()
                        else:
                            encrypted_credentials[key] = value
                    except(TypeError,AttributeError) as e:
                        raise ce.SavePasswordError(f"Error encoding the password: {e}")
                encrypted_credentials_list.append(encrypted_credentials)
            password_encrypted_base64[site] = encrypted_credentials_list
        try:
            with open(file_password, 'w') as f:
                json.dump(password_encrypted_base64, f)
        except (FileNotFoundError, PermissionError, OSError, IOError) as e:
            raise ce.SavePasswordError(f"Error saving the password to the file: {e}")

    @classmethod
    def load_password(cls, file_password):
        if not os.path.exists(file_password):
            return {}
        with open(file_password, 'r') as f:
            content = f.read()
            if content.strip():  # Verificar si el contenido no está vacío
                password_encrypted_base64 = json.loads(content)
                # Convertir los datos codificados en base64 a bytes
                password_encrypted = {}
                for site, credentials_list in password_encrypted_base64.items():
                    decrypted_credentials_list = []
                    for credentials in credentials_list:
                        decrypted_credentials = {}
                        for key, value in credentials.items():
                            if isinstance(value, str):
                                # Decodificar en base64 solo si el valor es una cadena
                                decrypted_credentials[key] = base64.b64decode(value)
                            else:
                                decrypted_credentials[key] = value
                        decrypted_credentials_list.append(decrypted_credentials)
                    password_encrypted[site] = decrypted_credentials_list
                return password_encrypted
            else:
                return {}

    @classmethod
    def search_password(cls,site, password_encrypted, private_pem):
        try:
            
            if site not in password_encrypted:
                raise ce.SiteNotFound("Site not found")
            
            print("\nCredentials found for", site)
            for credentials in password_encrypted[site]:

                user_name_encrypted = credentials['user_name']
                password_encrypted = credentials['password']
                user_name_decrypted = eu.decrypt(user_name_encrypted, private_pem)
                password_decrypted = eu.decrypt(password_encrypted, private_pem)

                print(f"User_name: {user_name_decrypted}, Password: {password_decrypted}")
        except ce.SiteNotFound as e:
            print(f"Error: {e}")

    @classmethod
    def delete_password(cls,site,user_name, password_encrypted, file_password, password_path_key, private_pem):
        try:
            if site not in password_encrypted:
                raise ce.SiteNotFound("Site not found")
                
            credentials_list = password_encrypted[site]
            updated_credentials_list = []
            matching_user_name = False
            for credentials in credentials_list:
                user_name_encrypted = credentials['user_name']
                user_name_decrypted = eu.decrypt(user_name_encrypted, private_pem)
                if user_name_decrypted != user_name:
                    updated_credentials_list.append(credentials)
                else:
                    matching_user_name = True

            if not matching_user_name:
                raise ce.UserNameNotFound("User name not found")
            
            if not cls.confirmation_master_password(password_path_key):
                return
            
            password_encrypted[site] = updated_credentials_list
            cls.save_password(password_encrypted, file_password)
            print("Password deleted successfully")

        except (ce.SiteNotFound,ce.UserNameNotFound,ce.PasswordEmpty,ce.PasswordIncorrect) as e:
            print(f"Error: {e}")


    @classmethod
    def add_password(cls,site,user_name,option, password_encrypted, public_pem, file_password):
        try:
            if option.lower() == "y":
                password = eu.random_password()
            elif option.lower() == "n":
                password = getpass.getpass("Password: ")
            else:
                raise ce.InvalidOption("Invalid Option")
        except ce.InvalidOption as e:            
            print(f"Error: {e}")
            
        new_credentials = {'user_name': eu.encrypt(user_name, public_pem), 'password': eu.encrypt(password, public_pem)}
        if site in password_encrypted:
            password_encrypted[site].append(new_credentials)
        else:
            password_encrypted[site] = [new_credentials]

        try:
            cls.save_password(password_encrypted, file_password)
            print("Password added successfully")
            print(f"Site/Web: {site}, User_name: {user_name}, Password: {password}")
        except (ce.SavePasswordError,) as e:
            print(f"Error: {e}")

    @classmethod
    def show_password(cls, password_encrypted, private_pem):
        print("\nShowing all passwords...\n")
        for site, credentials_list in password_encrypted.items():
            print(f"Site: {site}")
            for credentials in credentials_list:
                user_name_encrypted = credentials['user_name']
                decrypted_user_name = eu.decrypt(user_name_encrypted, private_pem)
                password_encrypted = credentials['password']
                decrypted_password = eu.decrypt(password_encrypted, private_pem)
                print(f"User_name: {decrypted_user_name}, Password: {decrypted_password}")
            print()

    @classmethod
    def create_file_keys(cls, private_key_path, public_key_path, password):
        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            private_pem, public_pem = eu.generate_key()
            master_key, salt = eu.derive_key_from_password(password)

            encrypted_private_key = eu.encrypt_keys(private_pem, master_key, salt)
            encrypted_public_key = eu.encrypt_keys(public_pem, master_key, salt)

            with open(private_key_path, 'wb') as f:
                f.write(encrypted_private_key)
            with open(public_key_path, 'wb') as f:
                f.write(encrypted_public_key)

            salt_path = private_key_path + '.salt'
            with open(salt_path, 'wb') as f:
                f.write(salt)
                Functions.restrict_access(salt_path)
        else:
            with open(private_key_path, 'rb') as f:
                encrypted_private_key = f.read()
            with open(public_key_path, 'rb') as f:
                encrypted_public_key = f.read()

            salt_path = private_key_path + '.salt'
            with open(salt_path, 'rb') as f:
                salt = f.read()

        master_key, _ = eu.derive_key_from_password(password, salt)

        private_pem = eu.decrypt_keys(encrypted_private_key, master_key, salt)
        public_pem = eu.decrypt_keys(encrypted_public_key, master_key, salt)

        return private_pem, public_pem
    
  