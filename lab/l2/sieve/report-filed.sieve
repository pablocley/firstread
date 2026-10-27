# IMAPSieve, a message copied or moved by the mailbox owner into a folder of their own: filing
# mail away means it was wanted (mox's automatic junk flags do the same). Inbox, Junk, Trash,
# Sent and Drafts say nothing, or are reported by the other scripts.
require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];
if environment :matches "imap.mailbox" "*" {
    set "to" "${1}";
}
if string :comparator "i;ascii-casemap" "${to}" ["INBOX", "Junk", "Trash", "Sent", "Drafts"] {
    stop;
}
if environment :matches "imap.user" "*" {
    set "user" "${1}";
}
pipe :copy :try "firstread-feedback" ["not_junk", "${user}"];
