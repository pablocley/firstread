require ["fileinto"];
if header :contains "Subject" "Project Acme" { fileinto "Acme"; }
