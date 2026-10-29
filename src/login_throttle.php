<?php
declare(strict_types=1);

function login_client_ip(): ?string
{
    $remoteAddress = $_SERVER['REMOTE_ADDR'] ?? null;

    if (!is_string($remoteAddress)) {
        return null;
    }

    $packedAddress = inet_pton($remoteAddress);
    return $packedAddress === false ? null : inet_ntop($packedAddress);
}

function login_attempt_email_key(string $email): string
{
    $normalizedEmail = strtolower(trim($email));
    $printableEmail = preg_replace('/[^\x20-\x7e]/', '?', $normalizedEmail);
    $printableEmail ??= '';

    if (strlen($printableEmail) <= 160) {
        return $printableEmail;
    }

    return substr($printableEmail, 0, 90) . ':' . hash('sha256', $normalizedEmail);
}

function login_throttle_minutes(string $email, ?string $ipAddress): int
{
    $checks = [['email', 'email']];

    if ($ipAddress !== null) {
        $checks[] = ['ip', 'ip'];
    }

    $retryMinutes = 0;

    foreach ($checks as [$column, $parameter]) {
        $statement = db()->prepare(
            "SELECT GREATEST(
                1,
                CEIL(TIMESTAMPDIFF(
                    SECOND,
                    NOW(),
                    DATE_ADD(attempted_at, INTERVAL 15 MINUTE)
                ) / 60)
             ) AS retry_minutes
             FROM login_attempts
             WHERE {$column} = :{$parameter}
               AND attempted_at >= DATE_SUB(NOW(), INTERVAL 15 MINUTE)
             ORDER BY attempted_at DESC
             LIMIT 1 OFFSET 4"
        );

        if ($parameter === 'ip') {
            $statement->bindValue(':ip', $ipAddress, PDO::PARAM_STR);
        } else {
            $statement->bindValue(':email', $email, PDO::PARAM_STR);
        }

        $statement->execute();
        $remaining = $statement->fetchColumn();

        if ($remaining !== false) {
            $retryMinutes = max($retryMinutes, (int) $remaining);
        }
    }

    return $retryMinutes;
}

function record_failed_login(string $email, ?string $ipAddress): void
{
    $statement = db()->prepare(
        'INSERT INTO login_attempts (email, ip)
         VALUES (:email, :ip)'
    );
    $statement->bindValue(':email', $email, PDO::PARAM_STR);

    if ($ipAddress === null) {
        $statement->bindValue(':ip', '', PDO::PARAM_STR);
    } else {
        $statement->bindValue(':ip', $ipAddress, PDO::PARAM_STR);
    }

    $statement->execute();
}

function clear_login_attempts(string $email, ?string $ipAddress): void
{
    if ($ipAddress === null) {
        $statement = db()->prepare('DELETE FROM login_attempts WHERE email = :email');
        $statement->execute(['email' => $email]);
        return;
    }

    $statement = db()->prepare(
        'DELETE FROM login_attempts WHERE email = :email OR ip = :ip'
    );
    $statement->bindValue(':email', $email, PDO::PARAM_STR);
    $statement->bindValue(':ip', $ipAddress, PDO::PARAM_STR);
    $statement->execute();
}
