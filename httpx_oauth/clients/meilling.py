from typing import Any, Dict, List, Optional, Tuple, cast

import httpx

from httpx_oauth.errors import GetIdEmailError
from httpx_oauth.oauth2 import BaseOAuth2

BASE_SCOPES = ["openid", "email"]


class MeillingOAuth2(BaseOAuth2[BaseOAuth2[Dict[str, Any]]]):
    def __init__(
        self,
        client_id: str,
        client_secret: str,
        meilling_base_url: str,
        scopes: Optional[List[str]] = BASE_SCOPES,
        name: str = "meilling",
    ):
        super().__init__(
            client_id,
            client_secret,
            f"https://{meilling_base_url}/v1/oauth2/auth",
            f"https://{meilling_base_url}/v1/oauth2/token",
            f"https://{meilling_base_url}/v1/oauth2/token",
            f"https://{meilling_base_url}/v1/oauth2/revoke",
            name=name,
            base_scopes=scopes,
        )
        self.profile = f"https://{meilling_base_url}/v1/oauth2/userinfo"

    async def get_id_email(self, token: str) -> Tuple[str, str]:
        async with httpx.AsyncClient(
            headers={**self.request_headers, "Authorization": f"Bearer {token}"}
        ) as client:
            response = await client.get(self.profile)

            if response.status_code >= 400:
                raise GetIdEmailError(response.json())

            data = cast(Dict[str, Any], response.json())

            user_id = data["sub"]
            email = data["email"]

            return str(user_id), email
