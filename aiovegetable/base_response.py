import typing

import pydantic


__all__: list[str] = ["ErrorDetails", "BaseResponse"]


class ErrorDetails(pydantic.BaseModel):
    type: str
    explanation: str
    details: typing.Optional[str]


class BaseResponse(pydantic.BaseModel):
    success: typing.Optional[bool]
    error: typing.Optional[bool]
    error_details: typing.Optional[ErrorDetails] = pydantic.Field(alias="errorDetails")
