# IMAPSieve, a message copied or moved into Junk by the mailbox owner: tell firstread.
require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];
if environment :matches "imap.user" "*" {
    set "user" "${1}";
}
pipe :copy :try "firstread-feedback" ["junk", "${user}"];
