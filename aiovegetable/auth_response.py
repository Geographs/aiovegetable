import typing

from aiovegetable import base_response


__all__: list[str] = ["LicenseInfo", "AuthResponse"]


class LicenseInfo(base_response.BaseResponse):
    expired: bool
    type: typing.Optional[str]
    expiration: typing.Optional[str]


class AuthResponse(base_response.BaseResponse):
    nonce: typing.Optional[str]
    license_info: typing.Optional[LicenseInfo]
    variables: typing.Optional[dict[str, typing.Any]]
