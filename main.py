import json
import os
import sys
import asyncio as aio
import aiohttp
from aiohttp import web
import jwt


# Client ID from project "usable-auth-library", configured for
# general purpose API testing
CLIENT_ID = '764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com'
CLIENT_SECRET = 'd-FL95Q19q7MQmFpd7hHD0Ty'
URL = (f'https://accounts.google.com/o/oauth2/v2/auth?'
       f'scope=openid+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email'
       '+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile&'
       f'redirect_uri=http%3A%2F%2Flocalhost%3A8085%2F&'
       f'response_type=code&'
       f'client_id={CLIENT_ID}&'
       f'access_type=offline')
# Obtained from 'https://accounts.google.com/.well-known/openid-configuration#jwks_uri'
GOOGLE_KEY_URL = 'https://www.googleapis.com/oauth2/v3/certs'


async def exchange_token(code: str):
    async with aiohttp.ClientSession() as session:
        data = {
            'code': code,
            'redirect_uri': 'http://localhost:8085/',
            'client_id': CLIENT_ID,
            'client_secret': CLIENT_SECRET,
            'scope': 'openid',
            'grant_type': 'authorization_code',
        }
        async with session.post('https://oauth2.googleapis.com/token', data=data) as resp:
            print('Response status:', resp.status)
            token_json = await resp.text()

        print('Response tokens (JSON):')
        print(token_json)
        print()
        token_dict = json.loads(token_json)
        id_token = token_dict['id_token']
        print('ID Token Header:')
        idt_header = jwt.get_unverified_header(id_token)
        print(idt_header)
        kid = idt_header['kid']

        jwks_client = jwt.PyJWKClient(GOOGLE_KEY_URL)
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)

        print('ID Token Claim:')
        payload = jwt.decode(id_token,
                             key=signing_key.key,
                             algorithms=['RS256'],
                             audience=CLIENT_ID)
        print(payload)
        exit(0)


async def handler(request: web.Request):
    query = request.query
    print('code=', query['code'])
    aio.create_task(exchange_token(query['code']))
    return web.Response(text="Done")


def main():
    print(URL)
    if sys.platform == "darwin":
        os.spawnlp(os.P_NOWAIT, 'open', 'open', URL)
    else:
        os.spawnlp(os.P_NOWAIT, 'xdg-open', 'xdg-open', URL)

    app = web.Application()
    app.add_routes([web.get('/', handler)])
    web.run_app(app, port=8085)


if __name__ == '__main__':
    main()
