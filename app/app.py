import sys
sys.path.append('../EPID')
from Module import *
from service import *
import mail

from flask import *
import random
import string
import time
import os

app = Flask(__name__)
app.secret_key = 'super secret key'
app.config['SESSION_TYPE'] = 'filesystem'

vaild_groups = [('NTU', 'ntu.edu.tw'), ('NTUCSIE', 'csie.ntu.edu.tw')]
services = [Service('ntu', 'service/ntu'), Service('ntucsie', 'service/ntucsie')]
TMP_PATH = 'tmp'
DEBUG = False

def random_str(n):
	sample = string.ascii_letters + string.digits
	return ''.join(random.SystemRandom().choice(sample) for _ in range(n))

def check_uid():
	if 'uid' not in session:
		session['uid'] = random_str(16)
	# DEBUG
	print session

@app.route('/')
def index():
	check_uid()

	if 'login' in session and session['login']:
		msg = 'You are logged in'
	else:
		msg = 'You are not logged in'
	return render_template('index.html', msg=msg)

@app.route('/login', methods=['GET', 'POST'])
def login():
	check_uid()
	if 'g_verify' not in session or not session['g_verify']:
		return redirect(url_for('index'))

	gid = session['gid']
	bsn = services[gid].bsnStr
	if request.method == 'GET':
		chall = 'CHALL' + random_str(16)
		session['chall'] = chall
		return render_template('login.html', bsn=bsn, chall=chall)

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

		gid = session['gid']
		ret = services[gid].verifier.verify(sign_dst, msgStr=session['chall'])
		if not ret:
			print ' * Verification failed'
			return redirect(request.url)

		session['login'] = True
		print ' * Verification success'
		return redirect(url_for('index'))

@app.route('/logout')
def logout():
	check_uid()

	session['login'] = False
	return render_template('logout.html')

def check_group(group, email):
	"""
	Return code:
		>= 0: group id
		-1: group not found
		-2: incorrect suffix
	"""
	for i, (g, suf) in enumerate(vaild_groups):
		if group == g:
			if email.endswith(suf):
				return i
			return -2
	return -1

@app.route('/send_email', methods=['GET', 'POST'])
def send_email():
	check_uid()

	if request.method == 'GET':
		msg = 'Please enter your email for verification'
	if request.method == 'POST':
		# TODO: Handle error
		if 'group' not in request.form:
			return redirect(request.url)
		if 'email' not in request.form:
			return redirect(request.url)

		group, email = request.form['group'], request.form['email']
		gid = check_group(group, email)
		if gid == -1:
			msg = 'Error: Unknown group'
			return render_template('send_email.html', msg=msg)
		elif gid == -2:
			msg = 'Error: Email does not end with correct suffix'
			return render_template('send_email.html', msg=msg)

		session['gid'] = gid
		session['g_verify'] = False
		session['code'] = random_str(32)
		session['code_expire'] = int(time.time()) + 600

		to = request.form['email']
		url = 'http://127.0.0.1:5000/verify_email?code=' + session['code']

		print ' * Sending email to', to
		print ' * url:', url
		if not DEBUG:
			mail.send_verify_email(to, url)
		msg = 'Verification email has sent to your mailbox'

	return render_template('send_email.html', msg=msg)

@app.route('/verify_email')
def verify_email():
	check_uid()

	code = request.args.get('code')
	if not code:
		return redirect(url_for('index'))
	if 'code' not in session:
		return redirect(url_for('index'))

	msg = ''
	if code != session['code']:
		msg = 'Error: Incorrect code'
	elif session['code_expire'] < int(time.time()):
		msg = 'Error: Code has expired'
	else:
		session['g_verify'] = True
		msg = 'Verification success'
	return render_template('verify_email.html', msg=msg)

@app.route('/join_group', methods=['GET', 'POST'])
def join_group():
	check_uid()
	if 'g_verify' not in session or not session['g_verify']:
		return redirect(url_for('index'))

	msg = ''
	gid = session['gid']
	bsn = services[gid].bsnStr
	if request.method == 'POST':
		if 'join_req' not in request.files:
			return redirect(request.url)
		f = request.files['join_req']
		if not f:
			return redirect(request.url)

		# save file
		join_dst = os.path.join(TMP_PATH, 'JOIN' + session['uid'])
		f.save(join_dst)
		msg = 'Upload success, key generated'

		# generate temp member private key
		key_name = 'KEY' + session['uid']
		key_dst = os.path.join(TMP_PATH, key_name)
		services[gid].issuer.generate_tmpmemkey(join_dst, key_dst)

	return render_template('join_group.html', msg=msg, bsn=bsn)

@app.route('/download')
def download():
	check_uid()
	if 'g_verify' not in session or not session['g_verify']:
		return redirect(url_for('index'))

	filename = request.args.get('file')
	if filename == 'gpubkey':
		gid = session['gid']
		path = 'service/' + services[gid].name
		filename = services[gid].name + '.pubkey'
		return send_from_directory(path, filename, as_attachment=True, attachment_filename=filename)
	elif filename == 'tmpmemkey':
		# Response 404 if not found
		key_name = 'KEY' + session['uid']
		return send_from_directory('tmp', key_name, as_attachment=True, attachment_filename='member.tmpmemkey')
	return redirect(url_for('index'))

@app.route('/test')
def test():
	return render_template('test.html')

if __name__ == '__main__':
	app.run()