require ["fileinto", "imap4flags", "variables"];
if header :matches "X-Firstread-Keywords" "*" {
    addflag "${1}";
}
if header :is "X-Firstread-Folder" "junk" {
    fileinto "Junk";
} elsif header :is "X-Firstread-Folder" "later" {
    fileinto "Later";
} else {
    keep;
}
