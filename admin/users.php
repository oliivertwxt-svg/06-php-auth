<?php
declare(strict_types=1);

require_once dirname(__DIR__) . '/bootstrap.php';

require_role('admin');
$admin = current_user();

if ($admin === null) {
    redirect('../login.php');
}

$errors = [];
$successMessage = flash('success');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify($_POST['_csrf'] ?? null)) {
        http_response_code(403);
        exit('Invalid or expired form token. Please reload the page and try again.');
    }

    $targetId = $_POST['user_id'] ?? null;
    $newRole = $_POST['role'] ?? null;
    if (
        (!is_string($targetId) && !is_int($targetId))
        || !ctype_digit((string) $targetId)
        || !is_string($newRole)
        || !in_array($newRole, ['user', 'admin'], true)
    ) {
        http_response_code(400);
        exit('Invalid role update request.');
    }

    $targetId = (int) $targetId;
    if ($targetId === (int) $admin['id'] && $newRole !== 'admin') {
        $errors[] = 'You cannot remove your own admin role.';
    } else {
        $statement = db()->prepare('SELECT id FROM users WHERE id = :id LIMIT 1');
        $statement->execute(['id' => $targetId]);

        if ($statement->fetch() === false) {
            $errors[] = 'That user no longer exists.';
        } else {
            $statement = db()->prepare('UPDATE users SET role = :role WHERE id = :id');
            $statement->execute([
                'role' => $newRole,
                'id' => $targetId,
            ]);

            flash('success', 'User role updated.');
            redirect('users.php');
        }
    }
}

$statement = db()->query(
    'SELECT id, name, email, role, created_at, last_login_at
     FROM users
     ORDER BY created_at DESC, id DESC'
);
$users = $statement->fetchAll();
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manage users</title>
    <link rel="stylesheet" href="../assets/auth.css">
</head>
<body>
<main class="auth-shell">
    <section class="auth-card admin-card" aria-labelledby="page-title">
        <?php render_authenticated_nav($admin, '../'); ?>
        <p class="eyebrow">ADMINISTRATION</p>
        <h1 id="page-title">Manage users</h1>
        <p class="subtitle">Review accounts and manage administrator access.</p>

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

        <div class="table-scroll">
            <table class="user-table">
                <thead>
                <tr>
                    <th>Name</th>
                    <th>Email</th>
                    <th>Role</th>
                    <th>Created</th>
                    <th>Last login</th>
                    <th>Update role</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($users as $listedUser): ?>
                    <tr>
                        <td><?= e($listedUser['name']) ?></td>
                        <td><?= e($listedUser['email']) ?></td>
                        <td><?= e($listedUser['role']) ?></td>
                        <td><?= e($listedUser['created_at']) ?></td>
                        <td><?= e($listedUser['last_login_at'] ?? 'Never') ?></td>
                        <td>
                            <?php if ((int) $listedUser['id'] === (int) $admin['id']): ?>
                                <span>Cannot change your own role</span>
                            <?php else: ?>
                                <form class="role-form" method="post" action="users.php">
                                    <?= csrf_field() ?>
                                    <input type="hidden" name="user_id" value="<?= e($listedUser['id']) ?>">
                                    <label class="visually-hidden" for="role-<?= e($listedUser['id']) ?>">
                                        Role for <?= e($listedUser['name']) ?>
                                    </label>
                                    <select id="role-<?= e($listedUser['id']) ?>" name="role">
                                        <option value="user" <?= $listedUser['role'] === 'user' ? 'selected' : '' ?>>User</option>
                                        <option value="admin" <?= $listedUser['role'] === 'admin' ? 'selected' : '' ?>>Admin</option>
                                    </select>
                                    <button type="submit">Save</button>
                                </form>
                            <?php endif; ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </section>
</main>
</body>
</html>
