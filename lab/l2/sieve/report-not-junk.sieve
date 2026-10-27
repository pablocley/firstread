# IMAPSieve, a message copied or moved out of Junk by the mailbox owner: tell firstread, unless
# it went to Trash (deleting junk says nothing about it being wanted).
require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];
if environment :matches "imap.mailbox" "*" {
    set "to" "${1}";
}
if string "${to}" ["Trash", "Junk"] {
    stop;
}
if environment :matches "imap.user" "*" {
    set "user" "${1}";
}
pipe :copy :try "firstread-feedback" ["not_junk", "${user}"];
