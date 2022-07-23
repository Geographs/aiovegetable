import hashlib
import hmac
import json
import typing

import aiohttp
import pydantic
import rsa

from aiovegetable import auth_response
from aiovegetable import base_response
from aiovegetable import exceptions
from aiovegetable import registration_response
from aiovegetable import reset_response
from aiovegetable import utils


__all__: list[str] = ["Client"]


class Client:
    def __init__(
        self,
        aid: str,
        api_key: str,
        client_secret: str,
        rsa_private_key: typing.Optional[str] = None,
    ) -> None:
        self.aid: str = aid
        self.api_key: str = api_key
        self.client_secret: bytes = client_secret.encode()
        self.rsa_private_key: typing.Optional[rsa.PrivateKey] = (
            rsa.PrivateKey.load_pkcs1(rsa_private_key.encode())
            if rsa_private_key
            else None
        )

        self._client_session: aiohttp.ClientSession = aiohttp.ClientSession(
            "https://auth.vegetables.inc"
        )

    def _get_headers(self, data: dict[str, typing.Any]) -> dict[str, str]:
        return {
            "x-vege-signature": hmac.new(
                self.client_secret,
                json.dumps(data).encode("utf-8"),
                digestmod=hashlib.sha256,
            ).hexdigest()
        }

    async def _parse_response(
        self,
        response: aiohttp.ClientResponse,
        model: typing.Type[
            typing.Union[
                auth_response.AuthResponse,
                registration_response.RegistrationResponse,
                reset_response.ResetResponse,
            ]
        ],
    ) -> typing.Union[
        auth_response.AuthResponse,
        registration_response.RegistrationResponse,
        reset_response.ResetResponse,
    ]:
        response_model: typing.Union[
            auth_response.AuthResponse,
            registration_response.RegistrationResponse,
            reset_response.ResetResponse,
        ] = pydantic.parse_obj_as(model, await response.json())

        if response_model.error:
            raise exceptions.APIError(
                f"{response_model.error_details.type}: {response_model.error_details.explanation}"
            )

        return response_model

    async def _handle_request(
        self,
        path: str,
        data: dict[str, typing.Any],
        model: typing.Type[
            typing.Union[
                auth_response.AuthResponse,
                registration_response.RegistrationResponse,
                reset_response.ResetResponse,
            ]
        ],
    ) -> typing.Union[
        auth_response.AuthResponse,
        registration_response.RegistrationResponse,
        reset_response.ResetResponse,
    ]:
        async with self._client_session.post(
            path, json=data, headers=self._get_headers(data)
        ) as response:
            if utils.verify_hmac(
                (await response.text()).encode(),
                response.headers["x-vege-signature"],
                self.client_secret,
            ):
                return await self._parse_response(response, model)
            raise exceptions.APIError("failed to verify hmac")

    @typing.overload
    async def authenticate(
        self, username: str, password: str
    ) -> auth_response.AuthResponse:
        ...

    @typing.overload
    async def authenticate(
        self, username: str, password: str, *, hwid: str
    ) -> auth_response.AuthResponse:
        ...

    @typing.overload
    async def authenticate(
        self, username: str, password: str, *, nonce: str
    ) -> base_response.BaseResponse:
        ...

    @typing.overload
    async def authenticate(
        self, username: str, password: str, *, hash: str
    ) -> auth_response.AuthResponse:
        ...

    @typing.overload
    async def authenticate(
        self, username: str, password: str, *, hwid: str, nounce: str
    ) -> auth_response.AuthResponse:
        ...

    @typing.overload
    async def authenticate(
        self, username: str, password: str, *, hwid: str, hash: str
    ) -> auth_response.AuthResponse:
        ...

    @typing.overload
    async def authenticate(
        self, username: str, password: str, *, nonce: str, hash: str
    ) -> auth_response.AuthResponse:
        ...

    @typing.overload
    async def authenticate(
        self, username: str, password: str, *, hwid: str, nonce: str, hash: str
    ) -> auth_response.AuthResponse:
        ...

    async def authenticate(
        self,
        username: str,
        password: str,
        *,
        hwid: typing.Optional[str] = None,
        nonce: typing.Optional[str] = None,
        hash: typing.Optional[str] = None,
    ) -> auth_response.AuthResponse:
        data: dict[str, typing.Optional[str]] = {
            "username": username,
            "password": password,
            "hwid": hwid,
            "nonce": nonce,
            "aid": self.aid,
            "key": self.api_key,
        }

        if not hwid:
            data["hwid"] = utils.get_hwid()

        if not nonce:
            data["nonce"] = utils.generate_random_string()

        if hash:
            data["hash"] = hash

        model: auth_response.AuthResponse = await self._handle_request(
            "/api/v4/authenticate", data, auth_response.AuthResponse
        )

        if not model.nonce == data["nonce"]:
            raise exceptions.AuthError("nonce does not match")

        if self.rsa_private_key:
            if isinstance(model.variables, dict):
                for key in model.variables.keys():
                    model.variables[key] = utils.decrypt_variable(
                        model.variables[key], self.rsa_private_key
                    )

        return model

    @typing.overload
    async def register(
        self, username: str, password: str, license: str, contact: str
    ) -> base_response.BaseResponse:
        ...

    @typing.overload
    async def register(
        self, username: str, password: str, license: str, contact: str, *, hwid: str
    ) -> base_response.BaseResponse:
        ...

    async def register(
        self,
        username: str,
        password: str,
        license: str,
        contact: str,
        *,
        hwid: typing.Optional[str] = None,
    ) -> base_response.BaseResponse:
        data: dict[str, typing.Optional[str]] = {
            "username": username,
            "password": password,
            "hwid": hwid,
            "aid": self.aid,
            "key": self.api_key,
            "license": license,
            "contact": contact,
        }

        if not hwid:
            data["hwid"] = utils.get_hwid()

        return await self._handle_request(
            "/api/v4/register", data, registration_response.RegistrationResponse
        )

    @typing.overload
    async def reset(
        self, username: str, password: str, reset_key: str
    ) -> base_response.BaseResponse:
        ...

    @typing.overload
    async def reset(
        self, username: str, password: str, reset_key: str, *, hwid: str
    ) -> base_response.BaseResponse:
        ...

    async def reset(
        self,
        username: str,
        password: str,
        reset_key: str,
        hwid: typing.Optional[str] = None,
    ) -> base_response.BaseResponse:
        data: dict[str, typing.Optional[str]] = {
            "username": username,
            "password": password,
            "hwid": hwid,
            "aid": self.aid,
            "key": self.api_key,
            "resetKey": reset_key,
        }

        if not hwid:
            data["hwid"] = utils.get_hwid()

        return await self._handle_request(
            "/api/v4/reset", data, reset_response.ResetResponse
        )
