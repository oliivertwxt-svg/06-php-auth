<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/src/db.php';

if ($argc !== 2 || !filter_var($argv[1], FILTER_VALIDATE_EMAIL) || strlen($argv[1]) > 160) {
    fwrite(STDERR, "Usage: php promote-admin.php user@example.com\n");
    exit(2);
}

$email = strtolower(trim($argv[1]));
$statement = db()->prepare('SELECT id, role FROM users WHERE email = :email LIMIT 1');
$statement->execute(['email' => $email]);
$user = $statement->fetch();

if (!is_array($user)) {
    fwrite(STDERR, "No user found with that email address.\n");
    exit(1);
}

if ($user['role'] === 'admin') {
    fwrite(STDOUT, "This account is already an admin.\n");
    exit(0);
}

$statement = db()->prepare("UPDATE users SET role = 'admin' WHERE id = :id");
$statement->execute(['id' => (int) $user['id']]);
fwrite(STDOUT, "Admin role granted to {$email}.\n");
