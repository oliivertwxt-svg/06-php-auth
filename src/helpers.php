<?php
declare(strict_types=1);

function e(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function redirect(string $location): void
{
    header('Location: ' . $location, true, 303);
    exit;
}

function flash(string $key, ?string $message = null): ?string
{
    if ($message !== null) {
        $_SESSION['_flash'][$key] = $message;
        return null;
    }

    $value = $_SESSION['_flash'][$key] ?? null;
    unset($_SESSION['_flash'][$key]);

    if (empty($_SESSION['_flash'])) {
        unset($_SESSION['_flash']);
    }

    return is_string($value) ? $value : null;
}

function store_old(array $values): void
{
    $_SESSION['_old'] = $values;
}

function old(string $key, string $default = ''): string
{
    $value = $_SESSION['_old'][$key] ?? $default;
    unset($_SESSION['_old'][$key]);

    if (empty($_SESSION['_old'])) {
        unset($_SESSION['_old']);
    }

    return is_string($value) ? $value : $default;
}

function render_authenticated_nav(array $user, string $pathPrefix = ''): void
{
    echo '<nav class="auth-nav" aria-label="Account navigation">';
    echo '<a href="' . e($pathPrefix) . 'dashboard.php">Dashboard</a>';
    echo '<a href="' . e($pathPrefix) . 'profile.php">Profile</a>';

    if (($user['role'] ?? null) === 'admin') {
        echo '<a href="' . e($pathPrefix) . 'admin/users.php">Admin</a>';
    }

    echo '</nav>';
}

function is_safe_local_url(string $url): bool
{
    if (
        $url === ''
        || $url[0] !== '/'
        || str_starts_with($url, '//')
        || str_contains($url, '\\')
        || preg_match('/[\x00-\x20\x7f]/', $url) === 1
    ) {
        return false;
    }

    $parts = parse_url($url);

    return $parts !== false
        && !isset($parts['scheme'])
        && !isset($parts['host'])
        && !isset($parts['user'])
        && !isset($parts['pass'])
        && isset($parts['path'])
        && str_starts_with($parts['path'], '/')
        && !str_starts_with($parts['path'], '//');
}
