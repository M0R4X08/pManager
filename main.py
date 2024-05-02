from functions import Functions as pm
from encryption_utils import EncryptionUtils as eu
from custom_exceptions import CustomExceptions as ce
import os
import getpass

if __name__ == "__main__":

    file_password = "password.json"
    key_folder = "keys"
    password_folder = "pass"

    pm.create_directory(key_folder)
    pm.create_directory(password_folder)

    private_key_path = os.path.join(key_folder, 'private_key.pem')
    public_key_path = os.path.join(key_folder, 'public_key.pem')
    password_path_key = os.path.join(key_folder, 'password_key')
    password_folder_path = os.path.join(password_folder, file_password)
    
    while True:
        if not os.path.exists(password_path_key):
            print("Creating keys...")
            print("Create a master password:")
            password_key = getpass.getpass("Password: ")
            if password_key != "":
                password_hash = eu.hash_password(password_key)
                with open(password_path_key, 'wb') as f:
                    f.write(password_hash)
                    pm.clear_console()
                break
            else:
                print("Password cannot be empty")
        else:
            print("Insert master password:")
            password_key = getpass.getpass("Password: ")
            if password_key != "":
                with open(password_path_key, 'rb') as f:
                    password_hash = f.read()
                if eu.verify_password(password_hash, password_key):
                    print("\nCorrect password\n")
                    pm.clear_console()
                    break
                else:
                    print("\nIncorrect password\n")
            else:
                print("\nPassword cannot be empty\n")
                break
    
    private_pem, public_pem = pm.create_file_keys(private_key_path, public_key_path, password_key)
    
    if not os.path.exists(password_folder_path):
        with open(password_folder_path, 'wb') as f:
            f.write(b'{}')
    
    password_encrypted = pm.load_password(password_folder_path)
    while True:
        print("\nPassword Manager\n")
        print("\tOptions:")
        print("\t1. Add new password")
        print("\t2. Show all passwords")
        print("\t3. Search password")
        print("\t4. Delete password")
        print("\t5. Exit")
        option = input("\t\nChoose an option: ")

        if option == "1":
            pm.clear_console()
            site = input("Site: ")
            user_name = input("User name: ")
            option = input("Generate random password? (y/n):")
            pm.add_password(site,user_name,option,password_encrypted, public_pem, password_folder_path)
        elif option == "2":
           pm.clear_console()
           pm.show_password(password_encrypted, private_pem)
        elif option == "3":
            pm.clear_console()
            site = input("Site: ")
            pm.search_password(site,password_encrypted, private_pem)
        elif option == "4":
            pm.clear_console()
            site = input("Site: ")
            user_name = input("User_name: ")
            pm.delete_password(site,user_name,password_encrypted, password_folder_path, password_path_key, private_pem)
        elif option == "5":
            pm.clear_console()
            break
        else:
            print("Invalid option")
