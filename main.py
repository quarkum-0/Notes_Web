from website import create_app
from authlib.integrations.flask_client import OAuth

main = create_app()

oauth = OAuth(main)
google = oauth.register(
    name='google',
    client_id="google-oauth-client",
    client_secret="client_secret",
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
)

if __name__ == '__main__':
    main.run(debug=True)
