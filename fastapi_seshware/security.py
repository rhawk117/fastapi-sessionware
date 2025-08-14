import abc
from typing import Any, Literal, cast

from fastapi import Request, Response
from fastapi.openapi.models import APIKey, APIKeyIn, OAuth2, OAuthFlows, SecurityScheme
from fastapi.security.utils import get_authorization_scheme_param

from fastapi_seshware.signatures import IdGenerator, SignatureAdapter
from fastapi_seshware.exceptions import HttpSessionIdMissing

from fastapi_seshware.models import CookieOptions, SessionID, SessionSecurityOptions


SecurityTypes = Literal["apiKey", "http", "oauth2", "openIdConnect"]


class BaseSessionSecurity(abc.ABC):
    def __init__(
        self,
        config: SessionSecurityOptions,
        *,
        model: SecurityScheme,
        type: SecurityTypes,
    ) -> None:
        self.model: SecurityScheme = model
        self.type: SecurityTypes = type
        self.signer: SignatureAdapter = config.signer(
            secret_key=config.secret_key,
            key_salt=config.key_salt,
        )
        self.id_generator: IdGenerator = config.id_generator
        self.unauthorized_msg: str | None = config.unauthorized_msg
        self.forbidden_msg: str | None = config.forbidden_msg

    @abc.abstractmethod
    def get_session_id(self, request: Request) -> str | None:
        """
        Gets the session ID from the request.

        Parameters
        ----------
        request : Request

        Returns
        -------
        str | None
            The session ID if found, otherwise None.
        """

    def create_session_id(self) -> SessionID:
        """
        Creates a new session ID.

        Returns
        -------
        SessionID
            A named tuple containing the unsigned and signed session IDs.
        """
        unsigned_id = self.id_generator()
        signed_id = self.signer.create_signature(unsigned_id)
        return SessionID(unsigned=unsigned_id, signed=signed_id)

    async def __call__(self, request: Request) -> SessionID:
        """
        Validates the session ID from the request.

        Parameters
        ----------
        request : Request

        Returns
        -------
        str
            The session ID if valid.

        Raises
        ------
        HttpSessionAuthError
            If the session ID is not found or invalid.
        """
        signed_sid: str | None = self.get_session_id(request)
        if signed_sid is None:
            raise HttpSessionIdMissing(
                detail=self.unauthorized_msg,
                model_name=self.__class__.__name__,
            )
        unsigned_id = self.signer.load_signature(signed_sid)
        if unsigned_id is None:
            raise HttpSessionIdMissing(
                detail=self.forbidden_msg,
                model_name=self.__class__.__name__,
            )

        sid = SessionID(
            unsigned=unsigned_id,
            signed=signed_sid,
        )

        request.state.session_id = sid

        return sid


def _api_key_scheme(
    name: str,
    in_: APIKeyIn,
    description: str | None = None,
) -> APIKey:
    return APIKey(
        **{"in": in_},  # type: ignore[arg-type]
        name=name,
        description=description,
    )


class SessionIDCookie(BaseSessionSecurity):
    def __init__(
        self,
        config: SessionSecurityOptions,
        cookie_options: CookieOptions = CookieOptions(),
        *,
        scheme_name: str = "ApiKeyCookie",
        description: str | None = None,
    ) -> None:
        if description is None:
            description = (
                "Reads server validated Session IDs that are sent by the client"
                f'in the "{cookie_options.cookie_name}" cookie and verifies the signature using {config.signer.__name__}.'
            )
        super().__init__(
            config,
            model=_api_key_scheme(
                cookie_options.cookie_name,
                APIKeyIn.cookie,
                description,
            ),
            type="apiKey",
        )
        self.scheme_name: str = scheme_name
        self.cookie_params: dict = cookie_options.model_dump(exclude={"cookie_name"})

    @property
    def cookie_name(self) -> str:
        return self.model.name  # type: ignore[return-value]

    def get_session_id(self, request: Request) -> str | None:
        return request.cookies.get(self.cookie_name)

    def set_cookie(self, response: Response, session_id: str | SessionID) -> None:
        if isinstance(session_id, SessionID):
            session_id = session_id.signed

        response.set_cookie(
            key=self.cookie_name,
            value=session_id,
            **self.cookie_params,
        )

    def delete_cookie(self, response: Response) -> None:
        response.delete_cookie(
            key=self.cookie_name,
            **self.cookie_params,
        )


class SessionIDHeader(BaseSessionSecurity):
    def __init__(
        self,
        config: SessionSecurityOptions,
        header_name: str = "X-Session-ID",
        *,
        scheme_name: str = "ApiKeyHeader",
        description: str | None = None,
    ) -> None:
        if description is None:
            description = (
                "Reads server validated Session IDs that are sent by the client"
                f'in the "{header_name}" header and verifies the signature using {config.signer.__name__}.'
            )
        super().__init__(
            config,
            model=_api_key_scheme(
                name=header_name,
                in_=APIKeyIn.header,
                description=description,
            ),
            type="apiKey",
        )
        self.scheme_name: str = scheme_name

    def get_session_id(self, request: Request) -> str | None:
        return request.headers.get(self.model.name)  # type: ignore[return-value]


class SessionIDQueryParam(BaseSessionSecurity):
    def __init__(
        self,
        config: SessionSecurityOptions,
        query_param_name: str = "session_id",
        *,
        scheme_name: str = "ApiKeyQuery",
        description: str | None = None,
    ) -> None:
        if description is None:
            description = (
                "Reads server validated Session IDs that are sent by the client"
                f'in the "{query_param_name}" query parameter and verifies the signature using {config.signer.__name__}.'
            )
        super().__init__(
            config,
            model=_api_key_scheme(
                name=query_param_name,
                in_=APIKeyIn.query,
                description=description,
            ),
            type="apiKey",
        )
        self.scheme_name: str = scheme_name

    @property
    def query_param_name(self) -> str:
        return self.model.name  # type: ignore[return-value]

    def get_session_id(self, request: Request) -> str | None:
        return request.query_params.get(self.query_param_name)


class OAuth2SessionIDBearer(BaseSessionSecurity):
    def __init__(
        self,
        config: SessionSecurityOptions,
        *,
        login_url: str,
        scheme_name: str | None = None,
        description: str | None = None,
        scopes: dict[str, str] | None = None,
    ) -> None:
        if description is None:
            description = (
                "Reads server validated Session IDs that are sent by the client"
                f"in the Authorization header as a Bearer token and verifies the signature using {config.signer.__name__}."
            )

        model = OAuth2(
            flows=OAuthFlows(
                implicit=cast(
                    Any,
                    {
                        "authorizationUrl": login_url,
                        "scopes": scopes or {},
                    },
                )
            )
        )
        if scheme_name is None:
            scheme_name = "OAuth2SessionBearer"
        super().__init__(
            config,
            model=model,
            type="oauth2",
        )

    def get_session_id(self, request: Request) -> str | None:
        """
        Extracts the session ID from the Authorization header in the format
        "Bearer <session_id>".
        """
        authorization = request.headers.get("Authorization")
        if not authorization:
            return None

        scheme, param = get_authorization_scheme_param(authorization)
        if scheme.lower() != "bearer":
            return None

        return param
