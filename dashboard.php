<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();
$user = current_user();

if ($user === null) {
    redirect('login.php');
}

$successMessage = flash('success');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Your dashboard</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-shell">
    <section class="auth-card dashboard-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Welcome, <?= e($user['name']) ?></h1>
        <p class="subtitle">You are signed in to your account.</p>

        <?php if ($successMessage !== null): ?>
            <p class="notice notice-success" role="status"><?= e($successMessage) ?></p>
        <?php endif; ?>

        <h2>Account details</h2>
        <dl class="account-details">
            <div><dt>Name</dt><dd><?= e($user['name']) ?></dd></div>
            <div><dt>Email</dt><dd><?= e($user['email']) ?></dd></div>
            <div><dt>Role</dt><dd><?= e($user['role']) ?></dd></div>
            <div><dt>Last login</dt><dd><?= e($user['last_login_at'] ?? 'Not available') ?> UTC</dd></div>
            <div><dt>Member since</dt><dd><?= e($user['created_at'] ?? 'Not available') ?></dd></div>
        </dl>

        <p class="auth-footer"><a href="profile.php">Edit profile and password</a></p>

        <form method="post" action="logout.php">
            <?= csrf_field() ?>
            <button class="button-secondary" type="submit">Sign out</button>
        </form>
    </section>
</main>
</body>
</html>
