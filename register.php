<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_guest();

$errors = [];
$name = '';
$email = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify($_POST['_csrf'] ?? null)) {
        http_response_code(403);
        exit('Invalid or expired form token. Please reload the page and try again.');
    }

    $postedName = $_POST['name'] ?? '';
    $postedEmail = $_POST['email'] ?? '';
    $name = is_string($postedName) ? trim($postedName) : '';
    $email = is_string($postedEmail) ? strtolower(trim($postedEmail)) : '';
    $password = $_POST['password'] ?? null;
    $confirmation = $_POST['confirm_password'] ?? null;
    store_old(['name' => $name, 'email' => $email]);

    $nameLength = preg_match_all('/./us', $name);
    if ($name === '' || $nameLength === false || $nameLength > 100) {
        $errors[] = 'Enter a name that is no more than 100 characters.';
    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254) {
        $errors[] = 'Enter a valid email address.';
    } else {
        $statement = db()->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
        $statement->execute(['email' => $email]);
        if ($statement->fetch() !== false) {
            $errors[] = 'An account with that email address already exists.';
        }
    }

    $passwordLength = is_string($password) ? preg_match_all('/./us', $password) : false;
    if (
        !is_string($password)
        || $passwordLength === false
        || $passwordLength < 10
        || preg_match('/\p{L}/u', $password) !== 1
        || preg_match('/\p{N}/u', $password) !== 1
    ) {
        $errors[] = 'Password must be at least 10 characters and include at least one letter and one number.';
    }

    if (is_string($password) && PASSWORD_DEFAULT === PASSWORD_BCRYPT && strlen($password) > 72) {
        $errors[] = 'Password cannot exceed 72 bytes with the current PHP password algorithm.';
    }

    if (!is_string($confirmation) || !is_string($password) || !hash_equals($password, $confirmation)) {
        $errors[] = 'Passwords do not match.';
    }

    if ($errors === []) {
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        try {
            $statement = db()->prepare(
                'INSERT INTO users (name, email, password_hash, last_login_at)
                 VALUES (:name, :email, :password_hash, UTC_TIMESTAMP())'
            );
            $statement->execute([
                'name' => $name,
                'email' => $email,
                'password_hash' => $passwordHash,
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
        establish_user_session((int) db()->lastInsertId(), 'user');
        flash('success', 'Your account has been created.');
        redirect('dashboard.php');
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
    <title>Create account</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-shell">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Create your account</h1>
        <p class="subtitle">Get started with a few details.</p>

        <?php if ($errors !== []): ?>
            <div class="notice notice-error" role="alert">
                <ul>
                    <?php foreach ($errors as $error): ?>
                        <li><?= e($error) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        <?php endif; ?>

        <form method="post" action="register.php">
            <?= csrf_field() ?>
            <label for="name">Name</label>
            <input id="name" name="name" type="text" maxlength="100" autocomplete="name" required value="<?= e($name) ?>">

            <label for="email">Email</label>
            <input id="email" name="email" type="email" maxlength="254" autocomplete="email" required value="<?= e($email) ?>">

            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="new-password" required>
            <p class="field-hint">At least 10 characters, including a letter and a number. The current PHP default also limits it to 72 bytes.</p>

            <label for="confirm_password">Confirm password</label>
            <input id="confirm_password" name="confirm_password" type="password" autocomplete="new-password" required>

            <button type="submit">Create account</button>
        </form>

        <p class="auth-footer">Already have an account? <a href="login.php">Sign in</a></p>
    </section>
</main>
</body>
</html>
