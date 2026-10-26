require ["vnd.dovecot.filter", "editheader"];
if not filter "firstread-filter" {
    deleteheader "X-Firstread-Folder";
    deleteheader "X-Firstread-Keywords";
}
