<?php
declare(strict_types=1);

$databasePassword = getenv('DB_PASSWORD');

define('DB_HOST', getenv('DB_HOST') ?: '127.0.0.1');
define('DB_NAME', getenv('DB_NAME') ?: 'swd_auth');
define('DB_USER', getenv('DB_USER') ?: 'root');
define('DB_PASSWORD', $databasePassword === false ? '' : $databasePassword);
