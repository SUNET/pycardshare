
from memcard import memcard
import struct
import sys
from secretsharing import PlaintextToHexSecretSharer


def cardshare():
    cmd = sys.argv[1]

    if cmd in ('split','s'):
        secret = sys.argv[2]
        thold = int(sys.argv[3])
        total = int(sys.argv[4])
        sys.stdout.write("Splitting secret into %d (%d) parts ... " % (total,thold))
        sys.stdout.flush()
        shares = PlaintextToHexSecretSharer.split_secret(secret, thold, total)
        print "Done"
        for share in shares:
            (n,sep,rest) = share.partition("-")
            n = int(n)
            packet = struct.pack("6B%ds" % len(rest),0xff,0x01,n,thold,total,len(rest),rest)
            nbytes = 8+len(rest)
            raw_input("Insert an empty card for secret %d and hit enter: " % n)
            with memcard() as card:
                card.write(20,packet)
            print repr(packet)
            print "Successfully wrote secret %d/%d (%d bytes) - please remove card from reader" % (n,total,nbytes)
    elif cmd in ('join','j'):
        shares = dict()
        enough = False
        w = "a"

        while not enough:
            raw_input("Insert %s card hit enter: " % w)
            with memcard() as card:
                header = card.read(20,6)
                print len(header)
                print repr(header)
                (m1, m2, n, thold, total, nbytes) = struct.unpack('6B', header)
                if m1 != 0xff and m2 != 1:
                    raise ValueError("This does not appear to be a valid card")

                print "This is card is part %d of a %d/%d scheme..." % (n, thold, total)
                secret = card.read(26, nbytes)
                share = "%d-%s" % (n, secret)
                shares[n] = share
                print shares
                enough = thold > 0 and thold <= len(shares)
                w = "another"

