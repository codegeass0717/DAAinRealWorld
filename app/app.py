import sys
sys.path.append('../EPID')
from Module import *
from util import *
import mail

from flask import *
import random
import string
import time
import os

app = Flask(__name__)
app.secret_key = 'super secret key'
app.config['SESSION_TYPE'] = 'filesystem'

TMP_PATH = 'tmp'
DEBUG = True

issuer = Issuer()
verifier = Member()

valid_groups = [('NTU', 'ntu.edu.tw'), ('NTUCSIE', 'csie.ntu.edu.tw')]
groups = [Group('ntu'), Group('ntucsie'), Group('ntu_service'), Group('ntucsie_service')]
services = [Service('aaaa', 0), Service('bbbb', 0), Service('cccc', 0)]

def generate_key(gid, join_dst, key_dst):
    global issuer, groups
    g = groups[gid]
    issuer.load(g.prvKeyFile, bsnFile=g.bsnFile)
    issuer.generate_tmpmemkey(join_dst, key_dst)

def verify_sign(sid, sign_dst, msgStr):
    global verifier, groups, services
    s = services[sid]
    g = groups[s.gid]
    verifier.load(g.pubKeyFile, None, bsnStr=s.bsn)
    name = str(verifier.get_pseudonym(sign_dst))
    return verifier.verify(sign_dst, msgStr=msgStr), name

def random_str(n):
    sample = string.ascii_letters + string.digits
    return ''.join(random.SystemRandom().choice(sample) for _ in range(n))

def check_uid():
    if 'uid' not in session:
        session['uid'] = random_str(16)
    if 'login' not in session:
        session['login'] = [False] * len(services)
    if 'name' not in session:
        session['name'] = [''] * len(services)
    # DEBUG
    print session

def check_group(group, email):
    """
    Return code:
        >= 0: group id
        -1: group not found
        -2: incorrect suffix
    """
    for i, (g, suf) in enumerate(valid_groups):
        if group == g:
            if email.endswith(suf):
                return i
            return -2
    return -1

def update(which, sid, value):
    # Deal with an unknown bug
    logins = session[which]
    logins[sid] = value
    session[which] = logins

@app.route('/')
def index():
    check_uid()

    msg = 'hi, there'
    return render_template('index.html', msg=msg)

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
    bsn = groups[gid].bsnStr
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
        generate_key(gid, join_dst, key_dst)

    return render_template('join_group.html', msg=msg, bsn=bsn)

@app.route('/login', methods=['GET', 'POST'])
def login():
    check_uid()

    sid = request.args.get('sid')
    if sid == None:
        return redirect(url_for('index'))
    sid = int(sid)
    if not 0 <= sid < len(services):
        return redirect(url_for('index'))

    bsn = services[sid].bsn
    g_name = groups[services[sid].gid].bsnStr
    if request.method == 'GET':
        chall = 'CHALL' + random_str(16)
        session['chall'] = chall
        return render_template('login.html', g_name=g_name, bsn=bsn, chall=chall)

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

        ret, name = verify_sign(sid, sign_dst, session['chall'])
        if not ret:
            print ' * Verification failed'
            return redirect(request.url)

        update('login', sid, True)
        update('name', sid, name)
        print ' * Verification success'
        return redirect(url_for('serv', sid=sid))

@app.route('/logout')
def logout():
    check_uid()

    sid = request.args.get('sid')
    if sid == None:
        return redirect(url_for('index'))
    sid = int(sid)
    if not 0 <= sid < len(services):
        return redirect(url_for('index'))

    update('login', sid, False)
    bsn = services[sid].bsn
    return render_template('logout.html', bsn=bsn)

@app.route('/download')
def download():
    check_uid()

    filename = request.args.get('file')
    if filename == 'group_verify':
        # Response 404 if not found
        sign_name = 'Groupverify' + session['uid']
        filename = 'Groupverify' + session['uid']
        return send_from_directory('tmp', sign_name, as_attachment=True, attachment_filename=filename)
    gid = session['gid']
    if filename == 'gpubkey':
        path = 'groups/' + groups[gid].name
        filename = groups[gid].name + '.pubkey'
        return send_from_directory(path, filename, as_attachment=True, attachment_filename=filename)
    elif filename == 'tmpmemkey':
        # Response 404 if not found
        key_name = 'KEY' + session['uid']
        filename = groups[gid].name + '.tmpmemkey'
        return send_from_directory('tmp', key_name, as_attachment=True, attachment_filename=filename)
    return redirect(url_for('index'))

@app.route('/test')
def test():
    return render_template('test.html')

@app.route('/entry')
def entry():
    return render_template('entry.html')

@app.route('/group_verify', methods=['GET', 'POST'])
def group_verify():
    global groups
    check_uid()
    signed_msg=""
    msg=""
    bsn =""
    bsn_tmp = ""
    gname = ""
    sid = request.args.get('sid')
    if(sid == '0' or sid == '1'):
        bsn_tmp = "NTUSERVICE"
        gname = "My group is NTU_Service. Please verify the message by ntu_service.pubkey"
    else:
        bsn_tmp = "NTUCSIESERVICE"
        gname = "My group is NTUCSIE_Service. Please verify the message by ntucsie_service.pubkey"

    bsn = "Basename is: " + bsn_tmp
    if request.method == 'POST':
        # TODO : Error Handling
        
        msg = "Auth" + request.form["msg"] + random_str(16)
        file_name = 'Groupverify' + session['uid']
        file_dst = os.path.join(TMP_PATH, file_name)

        if(sid == '0' or sid == '1'):
            verifier.load( groups[2].pubKeyFile, memKeyFile = groups[2].memKeyFile, bsnStr=bsn_tmp)
        else:
            verifier.load( groups[3].pubKeyFile, memKeyFile = groups[3].memKeyFile, bsnStr=bsn_tmp)
            
        verifier.sign(file_dst, None ,msg)
    signed_msg = "Signed Message is :" + msg

    return render_template('group_verify.html', signed_msg = signed_msg, bsn = bsn, gname = gname, sid = sid)

@app.route('/serv')
def serv():
    check_uid()

    sid = request.args.get('sid')
    if sid == None:
        return redirect(url_for('index'))
    sid = int(sid)
    if not 0 <= sid < len(services):
        return redirect(url_for('index'))

    if not session['login'][sid]:
        return redirect(url_for('login', sid=sid))

    if sid == 0 or sid == 1:
        msg = 'hi, ' + hex(int(session['name'][sid], 10))[2:8] + ". You are a member of NTU."
        return render_template('ntu_chat.html', msg=msg)
    elif sid == 2:
        msg = 'hi, ' + hex(int(session['name'][sid], 10))[2:8] + ". You are a member of NTU CSIE."
        return render_template('ntucsie_chat.html', msg=msg)
    else:
        return redirect(url_for('index'))

@app.route('/link')
def link():
    check_uid()

    step = request.args.get('step')
    step = int(step) if step else 0

    return render_template('link.html', step=step)

if __name__ == '__main__':
    app.run()
