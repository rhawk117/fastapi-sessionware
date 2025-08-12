import abc
from urllib.request import Request




class SessionFrontend(abc.ABC):





    async def get_session_id(self, request: Request)