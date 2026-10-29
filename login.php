<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_guest();

$errors = [];
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify($_POST['_csrf'] ?? null)) {
        http_response_code(403);
        exit('Invalid or expired form token. Please reload the page and try again.');
    }

    $postedEmail = $_POST['email'] ?? '';
    $email = is_string($postedEmail) ? strtolower(trim($postedEmail)) : '';
    $password = $_POST['password'] ?? null;
    store_old(['email' => $email]);

    if (!is_string($password) || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = 'Invalid email or password.';
    } else {
        $statement = db()->prepare(
            'SELECT id, password_hash, role
             FROM users
             WHERE email = :email
             LIMIT 1'
        );
        $statement->execute(['email' => $email]);
        $user = $statement->fetch();

        if (!is_array($user) || !password_verify($password, (string) $user['password_hash'])) {
            $errors[] = 'Invalid email or password.';
        } else {
            $userId = (int) $user['id'];
            $intendedUrl = $_SESSION['intended_url'] ?? null;

            if (password_needs_rehash((string) $user['password_hash'], PASSWORD_DEFAULT)) {
                $newHash = password_hash($password, PASSWORD_DEFAULT);
                $update = db()->prepare(
                    'UPDATE users
                     SET password_hash = :password_hash, last_login_at = UTC_TIMESTAMP()
                     WHERE id = :id'
                );
                $update->execute([
                    'password_hash' => $newHash,
                    'id' => $userId,
                ]);
            } else {
                $update = db()->prepare(
                    'UPDATE users SET last_login_at = UTC_TIMESTAMP() WHERE id = :id'
                );
                $update->execute(['id' => $userId]);
            }

            establish_user_session($userId, (string) $user['role']);

            if (is_string($intendedUrl) && is_safe_local_url($intendedUrl)) {
                redirect($intendedUrl);
            }

            redirect('dashboard.php');
        }
    }
}

$email = old('email', $email);
$successMessage = flash('success');
$flashError = flash('error');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Sign in</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Welcome back</h1>
        <p class="subtitle">Sign in to continue to your account.</p>

        <?php if ($successMessage !== null): ?>
            <p class="notice notice-success" role="status"><?= e($successMessage) ?></p>
        <?php endif; ?>
        <?php if ($flashError !== null): ?>
            <p class="notice notice-error" role="alert"><?= e($flashError) ?></p>
        <?php endif; ?>
        <?php foreach ($errors as $error): ?>
            <p class="notice notice-error" role="alert"><?= e($error) ?></p>
        <?php endforeach; ?>

        <form method="post" action="login.php">
            <?= csrf_field() ?>
            <label for="email">Email</label>
            <input id="email" name="email" type="email" maxlength="254" autocomplete="username" required value="<?= e($email) ?>">

            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required>

            <button type="submit">Sign in</button>
        </form>

        <p class="auth-footer">New here? <a href="register.php">Create an account</a></p>
    </section>
</main>
</body>
</html>
