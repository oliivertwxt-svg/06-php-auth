<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();
$user = current_user();

if ($user === null) {
    redirect('login.php');
}

$errors = [];
$successMessage = flash('success');
$name = (string) $user['name'];
$email = (string) $user['email'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify($_POST['_csrf'] ?? null)) {
        http_response_code(403);
        exit('Invalid or expired form token. Please reload the page and try again.');
    }

    $action = $_POST['action'] ?? null;

    if ($action === 'update_profile') {
        $postedName = $_POST['name'] ?? '';
        $postedEmail = $_POST['email'] ?? '';
        $name = is_string($postedName) ? trim($postedName) : '';
        $email = is_string($postedEmail) ? strtolower(trim($postedEmail)) : '';
        store_old(['name' => $name, 'email' => $email]);

        $nameLength = preg_match_all('/./us', $name);
        if ($name === '' || $nameLength === false || $nameLength > 100) {
            $errors[] = 'Enter a name that is no more than 100 characters.';
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
            $errors[] = 'Enter a valid email address.';
        } else {
            $statement = db()->prepare(
                'SELECT id FROM users WHERE email = :email AND id <> :id LIMIT 1'
            );
            $statement->execute([
                'email' => $email,
                'id' => (int) $user['id'],
            ]);
            if ($statement->fetch() !== false) {
                $errors[] = 'An account with that email address already exists.';
            }
        }

        if ($errors === []) {
            try {
                $statement = db()->prepare(
                    'UPDATE users SET name = :name, email = :email WHERE id = :id'
                );
                $statement->execute([
                    'name' => $name,
                    'email' => $email,
                    'id' => (int) $user['id'],
                ]);
            } catch (PDOException $exception) {
                $driverError = $exception->errorInfo[1] ?? null;
                if ($exception->getCode() !== '23000' || $driverError !== 1062) {
                    throw $exception;
                }

                $errors[] = 'An account with that email address already exists.';
            }
        }

        if ($errors === []) {
            flash('success', 'Your profile has been updated.');
            redirect('profile.php');
        }
    } elseif ($action === 'change_password') {
        $currentPassword = $_POST['current_password'] ?? null;
        $newPassword = $_POST['new_password'] ?? null;
        $confirmation = $_POST['confirm_password'] ?? null;

        $statement = db()->prepare('SELECT password_hash FROM users WHERE id = :id LIMIT 1');
        $statement->execute(['id' => (int) $user['id']]);
        $passwordHash = $statement->fetchColumn();

        if (
            !is_string($currentPassword)
            || !is_string($passwordHash)
            || !password_verify($currentPassword, $passwordHash)
        ) {
            $errors[] = 'Current password is incorrect.';
        }

        $passwordLength = is_string($newPassword) ? preg_match_all('/./us', $newPassword) : false;
        if (
            !is_string($newPassword)
            || $passwordLength === false
            || $passwordLength < 10
            || preg_match('/\p{L}/u', $newPassword) !== 1
            || preg_match('/\p{N}/u', $newPassword) !== 1
        ) {
            $errors[] = 'New password must be at least 10 characters and include at least one letter and one number.';
        }

        if (is_string($newPassword) && PASSWORD_DEFAULT === PASSWORD_BCRYPT && strlen($newPassword) > 72) {
            $errors[] = 'New password cannot exceed 72 bytes with the current PHP password algorithm.';
        }

        if (
            is_string($newPassword)
            && PASSWORD_DEFAULT === PASSWORD_BCRYPT
            && strlen($newPassword) > 72
        ) {
            $errors[] = 'New password cannot exceed 72 bytes with the current PHP password algorithm.';
        }

        if (!is_string($confirmation) || !is_string($newPassword) || !hash_equals($newPassword, $confirmation)) {
            $errors[] = 'New passwords do not match.';
        }

        if ($errors === []) {
            $newHash = password_hash($newPassword, PASSWORD_DEFAULT);
            $statement = db()->prepare(
                'UPDATE users SET password_hash = :password_hash WHERE id = :id'
            );
            $statement->execute([
                'password_hash' => $newHash,
                'id' => (int) $user['id'],
            ]);

            establish_user_session((int) $user['id'], (string) $user['role']);
            flash('success', 'Your password has been changed.');
            redirect('profile.php');
        }
    } else {
        http_response_code(400);
        exit('Invalid profile action.');
    }
}

$name = old('name', $name);
$email = old('email', $email);
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Account settings</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Account settings</h1>
        <p class="subtitle">Update your account details or change your password.</p>

        <?php if ($successMessage !== null): ?>
            <p class="notice notice-success" role="status"><?= e($successMessage) ?></p>
        <?php endif; ?>
        <?php if ($errors !== []): ?>
            <div class="notice notice-error" role="alert">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <h2>Profile</h2>
        <form method="post" action="profile.php">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="update_profile">
            <label for="name">Name</label>
            <input id="name" name="name" type="text" maxlength="100" autocomplete="name" required value="<?= e($name) ?>">

            <label for="email">Email</label>
            <input id="email" name="email" type="email" maxlength="254" autocomplete="email" required value="<?= e($email) ?>">

            <button type="submit">Save profile</button>
        </form>

        <h2>Change password</h2>
        <form method="post" action="profile.php">
            <?= csrf_field() ?>
            <input type="hidden" name="action" value="change_password">
            <label for="current_password">Current password</label>
            <input id="current_password" name="current_password" type="password" autocomplete="current-password" required>

            <label for="new_password">New password</label>
            <input id="new_password" name="new_password" type="password" autocomplete="new-password" required>
            <p class="field-hint">At least 10 characters, including a letter and a number. The current PHP default also limits it to 72 bytes.</p>

            <label for="confirm_password">Confirm new password</label>
            <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>

            <button type="submit">Change password</button>
        </form>

        <p class="auth-footer"><a href="dashboard.php">Back to dashboard</a></p>
    </section>
</main>
</body>
</html>
