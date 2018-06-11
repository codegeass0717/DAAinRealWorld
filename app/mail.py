import requests
import os

if 'MAIL_API_KEY' not in os.environ:
	print ' - Error: enviornment variable MAIL_API_KEY not set'
	exit(1)

MAIL_API_KEY = os.environ['MAIL_API_KEY']

def send_email(to, subject, text):
	data = {
		'from': 'Mailgun Sandbox <postmaster@sandbox9ab48217e4a34189ab342d5b6704d27b.mailgun.org>',
		'to': 'User <{}>'.format(to),
		'subject': subject,
		'text': text
	}

	return requests.post(
		'https://api.mailgun.net/v3/sandbox9ab48217e4a34189ab342d5b6704d27b.mailgun.org/messages',
		auth=('api', MAIL_API_KEY),
		data=data
	)

def send_verify_email(to, url):
	subject = 'Verification email'
	text = '''
		Please click the following link to continue.
		{}
	'''.format(url)
	send_email(to, subject, text)