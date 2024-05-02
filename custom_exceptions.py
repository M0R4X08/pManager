class CustomExceptions:
    class SiteNotFound(Exception):
        pass
    class UserNameNotFound(Exception):
        pass
    class PasswordEmpty(Exception):
        pass
    class PasswordIncorrect(Exception):
        pass
    class InvalidOption(Exception):
        pass
    class PermisionError(Exception):
        pass
    class SavePasswordError(Exception):
        pass