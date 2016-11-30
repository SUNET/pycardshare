from memcard import memcard
import struct
import sys
from smartcard import util as sutil
from secretsharing import PlaintextToHexSecretSharer
import os
import tempfile
import subprocess
import random
import string
import base64
import re

__usage__ = dict(
    cardshare="""

cardshare dup:
          duplicate/backup a card

cardshare split <secret> <# shares> <recovery threshold>:
          split <secret> into <# shares> pieces and write each to a new card. Require <recovery threshold>
          parts for recovery of secret

cardshare join
          prompt for enough cards to recover secret and print to stdout

cardshare info
          prompt for a card and print metadata about the card

          This tool is mostly useful for managing cards. You probably want to use the "keyshare"
          command to manage private PKCS8 keys splitting the symmetric key across multiple cards.

""",
    keyshare="""

keyshare new <name> <days> <subject> <recovery threshold> <# shares>:

        generate a new key and store the private key in <name>.key and the self-signed certificate as
        <name>.crt (PEM encoded) with SubjectDN set to <subject> and validity to <days> days.

keyshare use <name>

        recover the secret for <name>.key and write a temporary copy of the unencrypted keyfile to
        a tempfile in /dev/shm. A shell is opened with KEY set to the (temporary) keyfile and CERT
        set to the
    """)


def recover():
    shares = dict()
    enough = False
    w = "a"

    while not enough:
        (share, n, threshold, total) = read_share("Insert %s card hit enter: " % w)
        print "This is card is part %d of a %d/%d scheme..." % (n, threshold, total)
        shares[n] = share
        enough = threshold > 0 and threshold <= len(shares)
        w = "another"

    return PlaintextToHexSecretSharer.recover_secret(shares.values())


def write_share(share, threshold, total):
    (n, sep, rest) = share.partition("-")
    n = int(n)
    packet = struct.pack("6B%ds" % len(rest), 0xff, 0x01, n, threshold, total, len(rest), rest)
    nbytes = 8 + len(rest)
    raw_input("Insert an empty card for secret %d and hit enter: " % n)
    if os.environ.get("CARD") == "console":
        print "Card %d contents: %s" % (n, base64.b64encode(packet))
    else:
        with memcard() as card:
            card.write(0x20, packet)
    return n, nbytes


def read_share(msg):
    raw_input(msg)

    if os.environ.get("CARD") == "console":
        data = raw_input("Paste base64 encoded data: ")
        decoded_data = base64.b64decode(data)
        header_ch = list(decoded_data)
        header_str = re.split(".", decoded_data, 6)
        m1		= ord(header_ch[0])
        m2		= ord(header_ch[1])
        n		= ord(header_ch[2])
        threshold	= ord(header_ch[3])
        total		= ord(header_ch[4])
        nbytes		= ord(header_ch[5])
        secret		= header_str[6]
        if m1 != 0xff or m2 != 0x01:
            raise ValueError("This does not appear to be a valid card")
        share = "%d-%s" % (n, secret)
        return share, n, threshold, total
    else:
        with memcard() as card:
            header = card.read(0x20, 6)
            (m1, m2, n, threshold, total, nbytes) = header
            if m1 != 0xff or m2 != 0x01:
                raise ValueError("This does not appear to be a valid card")
    
            secret = card.read(0x26, nbytes)
            share = "%d-%s" % (n, sutil.toASCIIString(secret))
            return share, n, threshold, total


def split(secret, threshold, total):
    sys.stdout.write("Splitting secret into %d (%d) parts ... " % (total, threshold))
    sys.stdout.flush()
    shares = PlaintextToHexSecretSharer.split_secret(secret, threshold, total)
    print "Done"
    for share in shares:
        (n, nbytes) = write_share(share, threshold, total)
        print "Successfully wrote secret %d/%d (%d bytes) - please remove card from reader" % (n, total, nbytes)


def cardshare():
    if len(sys.argv) <= 1:
        print __usage__['cardshare']
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd in ('help','h'):
        print __usage__['cardshare']
    elif cmd in ('split', 's'):
        secret = sys.argv[2]
        threshold = int(sys.argv[3])
        total = int(sys.argv[4])
        split(secret, threshold, total)
    elif cmd in ('join', 'j', 'recover', 'r'):
        print recover()
    elif cmd in ('dup','backup','d'):
        (share, n, threshold, total) = read_share('Insert a card to backup and hit enter:')
        print "This is card is part %d of a %d/%d scheme..." % (n, threshold, total)
        write_share(share, threshold, total)
    elif cmd in ('info','i'):
        (share, n, threshold, total) = read_share("Insert a card and hit enter:")
        print "This is card is part %d of a %d/%d scheme..." % (n, threshold, total)


def keyshare():
    if len(sys.argv) <= 1:
        print __usage__['keyshare']
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd in ('help','h'):
        print __usage__['keyshare']
    elif cmd in ('new', 'generate', 'gen', 'n'):
        name = sys.argv[2]
        days = sys.argv[3]
        subject = sys.argv[4]
        threshold = int(sys.argv[5])
        total = int(sys.argv[6])
        password = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(40))
        sys.stdout.write("Generating key ... ")
        sys.stdout.flush()
        ret = subprocess.call(["openssl", "genrsa", "-out", "%s.key" % name,
                               "-aes256", "-passout", "pass:%s" % password, "4096"])
        if ret != 0:
            sys.exit(ret)
        print "Done"
        sys.stdout.write("Generating certificate ... ")
        sys.stdout.flush()
        ret = subprocess.call(["openssl", "req", "-x509", "-sha256", "-new", "-subj", subject, "-days", days,
                               "-passin", "pass:%s" % password, "-key", "%s.key" % name, "-out", "%s.crt" % name])
        if ret != 0:
            sys.exit(ret)

        print "Done"
        split(password, threshold, total)
    elif cmd in ('use', 'u'):
        tmpf = tempfile.NamedTemporaryFile(dir="/dev/shm")
        tmpfn = tmpf.name
        name = sys.argv[2]
        keyfile = "%s.key" % name
        certfile = "%s.crt" % name

        cmdline = ["/bin/bash"]
        if len(sys.argv) > 3:
            cmdline = sys.argv[3:]

        password = recover()
        ret = subprocess.call(["openssl", "rsa", "-passin", "pass:%s" % password, "-in", keyfile, "-out", tmpfn])
        password = ''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(200))
        del password
        if ret != 0:
            sys.exit(ret)

        print "Launching %s with KEY=%s and CERT=%s ..." % (" ".join(cmdline), keyfile, certfile)
        ret = subprocess.call(cmdline, env={"KEY":tmpfn, "CERT": certfile})
        sys.exit(ret)
