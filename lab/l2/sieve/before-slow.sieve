require ["vnd.dovecot.filter", "editheader"];
if not filter "firstread-filter-slow" {
    deleteheader "X-Firstread-Folder";
    deleteheader "X-Firstread-Keywords";
}
