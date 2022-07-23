__all__: list[str] = ["APIError", "AuthError"]


class APIError(Exception):
    pass


class AuthError(APIError):
    pass
