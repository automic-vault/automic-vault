# rclone

The hardener installs the signed rclone Isotope and encrypts the complete
`rclone.conf` with rclone's native configuration encryption. The generated
wrapping password is a Global Value applied through rclone's native password
command only to a verified rclone Target.

rclone keeps all remotes in one encrypted configuration. One approved Secret
Application therefore unlocks every configured remote for that rclone process;
this Gate cannot provide per-remote access control.
