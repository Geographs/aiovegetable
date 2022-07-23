import datetime

import pydantic

from aiovegetable import base_response


__all__: list[str] = ["ResetResponse"]


class ResetResponse(base_response.BaseResponse):
    next_reset: datetime.datetime = pydantic.Field(alias="nextReset")
