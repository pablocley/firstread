"""Deliver one message over Dovecot's LMTP socket, the way an MTA does."""
import smtplib, sys
sock, rcpt, sender, path = sys.argv[1:5]
c = smtplib.LMTP(sock)
c.ehlo("mx.lab.invalid")
r = c.sendmail(sender, [rcpt], open(path, "rb").read())
# sendmail raises unless at least one recipient was accepted; r maps refused recipients.
print("accepted" if not r else f"refused recipients: {r}")
c.quit()
