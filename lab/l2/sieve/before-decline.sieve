require ["vnd.dovecot.filter", "editheader"];
if not filter "firstread-filter-decline" {
    deleteheader "X-Firstread-Folder";
    deleteheader "X-Firstread-Keywords";
}
