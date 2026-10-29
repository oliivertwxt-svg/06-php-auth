# SWD Auth

A PHP 8 authentication example for XAMPP and MySQL. The application uses the
`swd_auth` database; `schema.sql` creates the database and the `users` and
`login_attempts` tables.

## Setup

1. Start Apache and MySQL in XAMPP.
2. Import `schema.sql` in phpMyAdmin.
3. Configure the database with environment variables `DB_HOST`, `DB_NAME`,
   `DB_USER`, and `DB_PASSWORD`. Defaults are `127.0.0.1`, `swd_auth`, `root`,
   and an empty password, respectively, for a typical local XAMPP install.
4. Open `http://localhost/swd/06-php-auth/register.php` to create an account.

Errors are displayed for local development in `bootstrap.php`; turn off
`display_errors` and configure private error logging before deploying.

## Security features

- Passwords are stored with PHP's `password_hash()` and checked with
  `password_verify()`. Login upgrades outdated hashes using
  `password_needs_rehash()`. Plaintext passwords, MD5, and SHA-1 are not used.
- Database access uses PDO prepared statements, exception mode, and native
  prepares.
- Authentication forms use per-session CSRF tokens verified with
  `hash_equals()`. Logout only accepts POST requests.
- Sessions use a dedicated name, strict mode, cookie-only transport, HttpOnly,
  SameSite=Lax, and the Secure cookie flag when HTTPS is active. Session IDs
  rotate at login and after password changes.
- Authenticated sessions expire after 30 minutes without activity.
- Intended login destinations are checked as local paths to prevent open
  redirects.
- Output rendered in HTML is escaped. Registration/profile validation and the
  database unique constraint protect email addresses from duplicates.
- Responses set `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, and
  `Referrer-Policy: strict-origin-when-cross-origin`.

## Account pages

- `register.php` creates a user account.
- `login.php` authenticates and routes to a validated intended local URL or the
  dashboard.
- `dashboard.php` displays account information and a POST sign-out form.
- `profile.php` updates the signed-in user's name/email or changes the password
  after verifying the current password.
