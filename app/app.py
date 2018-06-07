import sys
sys.path.append('../EPID')
from Module import *

from flask import *
from werkzeug.utils import secure_filename
import random
import string
import os

app = Flask(__name__)
app.secret_key = 'super secret key'
app.config['SESSION_TYPE'] = 'filesystem'

PUBKEY_PATH = 'config/testKey.pubkey'
PRVKEY_PATH = 'config/testKey.prvkey'
BASENAME_PATH = 'config/bsn'
TMP_PATH = 'tmp'
with open(BASENAME_PATH, 'r') as f:
	BASENAME = f.read()

issuer = Issuer()
verifier = Member()
verifier.load(PUBKEY_PATH, None, bsnStr=BASENAME)

def random_str(n):
	sample = string.ascii_letters + string.digits
	return ''.join(random.SystemRandom().choice(sample) for _ in range(n))

def check_uid():
	if 'uid' not in session:
		session['uid'] = random_str(16)

@app.route('/')
def index():
	if 'login' in session and session['login']:
		msg = 'You are logged in'
	else:
		msg = 'You are not logged in'
	return render_template('index.html', msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
	check_uid()

	if request.method == 'GET':
		chall = 'CHALL' + random_str(16)
		session['chall'] = chall
		return render_template('login.html', bsn=BASENAME, chall=chall)

	if request.method == 'POST':
		# TODO: Handle error
		if 'chall' not in session:
			return redirect(request.url)
		if 'signed_msg' not in request.files:
			return redirect(request.url)

		f = request.files['signed_msg']
		if not f:
			return redirect(request.url)
		sign_dst = os.path.join(TMP_PATH, session['chall'])
		f.save(sign_dst)

		if not verifier.verify(sign_dst, msgStr=session['chall']):
			print ' * Verification failed'
			return redirect(request.url)

		session['login'] = True
		print ' * Verification success'
		return redirect(url_for('index'))

@app.route('/logout')
def logout():
	session['login'] = False
	return render_template('logout.html')


@app.route('/join_group', methods=['GET', 'POST'])
def join_group():
	check_uid()

	msg = ''
	if request.method == 'POST':
		if 'join_req' not in request.files:
			return redirect(request.url)
		f = request.files['join_req']
		if not f:
			return redirect(request.url)

		# save file
		join_dst = os.path.join(TMP_PATH, 'JOIN' + session['uid'])
		f.save(join_dst)
		msg = 'Upload success'

		# generate temp member private key
		key_name = 'KEY' + session['uid']
		key_dst = os.path.join(TMP_PATH, key_name)
		issuer.generate_tmpmemkey(PRVKEY_PATH, BASENAME_PATH, join_dst, key_dst)

	return render_template('join_group.html', msg=msg, bsn=BASENAME)

@app.route('/download')
def download():
	check_uid()

	filename = request.args.get('file')
	if filename == 'gpubkey':
		return send_from_directory('config', 'testKey.pubkey', as_attachment=True, attachment_filename='testKey.pubkey')
	elif filename == 'tmpmemkey':
		# Response 404 if not found
		key_name = 'KEY' + session['uid']
		return send_from_directory('tmp', key_name, as_attachment=True, attachment_filename='member.tmpmemkey')
	return redirect(url_for('index'))

if __name__ == '__main__':
	app.run()