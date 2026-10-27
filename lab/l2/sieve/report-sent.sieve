# IMAPSieve, a copy reaching Sent: the owner wrote to its recipients.
require ["vnd.dovecot.pipe", "copy", "imapsieve", "environment", "variables"];
if environment :matches "imap.user" "*" {
    set "user" "${1}";
}
pipe :copy :try "firstread-feedback" ["sent", "${user}"];
