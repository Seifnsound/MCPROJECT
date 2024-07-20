import os
import json
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from flask import Flask, redirect, request, session, url_for, jsonify, render_template_string

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a random secret key

# Path to your client_secret.json file downloaded from Google Cloud Console
CLIENT_SECRETS_FILE = "client_secret.json"

# Scopes required by the application
SCOPES = ['https://www.googleapis.com/auth/content']

# OAuth 2.0 redirect URI
REDIRECT_URI = 'https://your-repl-url/oauth2callback'  # Replace with your Repl.it URL

@app.route('/')
def index():
    return render_template_string('''
        <h1>Welcome to Google Merchant Center Feed Enhancer</h1>
        <a href="/authorize">Login with Google</a>
    ''')

@app.route('/authorize')
def authorize():
    # Create flow instance to manage the OAuth 2.0 Authorization Grant Flow steps
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES)
    flow.redirect_uri = REDIRECT_URI

    # Generate the authorization URL
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )

    # Store the state in the session to verify the response later
    session['state'] = state

    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    # Specify the state when creating the flow in the callback to prevent CSRF attacks
    state = session['state']

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('oauth2callback', _external=True)

    # Use the authorization server's response to fetch the OAuth 2.0 tokens
    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    # Store credentials in the session
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)

    return redirect(url_for('choose_merchant'))

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

@app.route('/choose_merchant')
def choose_merchant():
    if 'credentials' not in session:
        return redirect('authorize')

    credentials = google.oauth2.credentials.Credentials(
        **session['credentials'])

    # Build the Google Merchant Center API service
    service = googleapiclient.discovery.build('content', 'v2.1', credentials=credentials)

    # List the Merchant Center accounts accessible by the user
    accounts = service.accounts().list(merchantId='insert_here_your_main_account_id').execute()
    account_choices = [(account['id'], account['name']) for account in accounts['resources']]

    return render_template_string('''
        <h1>Choose your Merchant Center Account</h1>
        <form action="/fetch_feed" method="post">
            <select name="merchant_id">
                {% for id, name in accounts %}
                <option value="{{ id }}">{{ name }}</option>
                {% endfor %}
            </select>
            <input type="submit" value="Fetch Feed">
        </form>
    ''', accounts=account_choices)

@app.route('/fetch_feed', methods=['POST'])
def fetch_feed():
    if 'credentials' not in session:
        return redirect('authorize')

    credentials = google.oauth2.credentials.Credentials(
        **session['credentials'])

    # Build the Google Merchant Center API service
    service = googleapiclient
