import typing

import pydantic

from aiovegetable import base_response


__all__: list[str] = [
    "RegistrationResponse",
]


class RegistrationResponse(base_response.BaseResponse):
    expiration: typing.Optional[str]
    license_type: typing.Optional[str] = pydantic.Field(alias="alias")
