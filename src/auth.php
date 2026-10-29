<?php
declare(strict_types=1);

function current_user(): ?array
{
    static $loaded = false;
    static $user = null;

    if ($loaded) {
        return $user;
    }
    $loaded = true;

    $userId = $_SESSION['user_id'] ?? null;
    if (!is_int($userId) && !(is_string($userId) && ctype_digit($userId))) {
        return null;
    }

    $statement = db()->prepare(
        'SELECT id, name, email, role, last_login_at, created_at
         FROM users
         WHERE id = :id
         LIMIT 1'
    );
    $statement->execute(['id' => (int) $userId]);
    $record = $statement->fetch();

    if (!is_array($record)) {
        unset($_SESSION['user_id'], $_SESSION['role'], $_SESSION['last_activity']);
        return null;
    }

    $_SESSION['role'] = (string) $record['role'];
    $user = $record;

    return $user;
}

function establish_user_session(int $userId, string $role): void
{
    if (!session_regenerate_id(true)) {
        throw new RuntimeException('Unable to rotate the session ID.');
    }

    $_SESSION['user_id'] = $userId;
    $_SESSION['role'] = $role;
    $_SESSION['last_activity'] = time();
    unset($_SESSION['intended_url'], $_SESSION['_old'], $_SESSION['_csrf_token']);
}

function require_login(): void
{
    if (current_user() !== null) {
        return;
    }

    $requestedUrl = $_SERVER['REQUEST_URI'] ?? '';
    if (is_string($requestedUrl) && is_safe_local_url($requestedUrl)) {
        $_SESSION['intended_url'] = $requestedUrl;
    }

    flash('error', 'Please log in to continue.');
    redirect('login.php');
}

function require_guest(): void
{
    if (current_user() !== null) {
        redirect('dashboard.php');
    }
}

function require_role(string $role): void
{
    require_login();
    $user = current_user();

    if ($user !== null && $user['role'] === $role) {
        return;
    }

    http_response_code(403);
    exit('Forbidden');
}

function enforce_idle_timeout(): void
{
    if (!isset($_SESSION['user_id'])) {
        return;
    }

    $now = time();
    $lastActivity = $_SESSION['last_activity'] ?? $now;

    if (!is_int($lastActivity) || $now - $lastActivity >= 1800) {
        $_SESSION = [];

        if (!session_regenerate_id(true)) {
            throw new RuntimeException('Unable to rotate the session ID.');
        }

        flash('error', 'Your session expired after 30 minutes of inactivity. Please log in again.');
        redirect('login.php');
    }

    $_SESSION['last_activity'] = $now;
}
