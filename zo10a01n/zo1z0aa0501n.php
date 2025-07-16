<?php
$host = 'db_host';
$dbname = 'db_name';
$username = 'db_username';
$password = 'db_password';

// Set DSN (Data Source Name)
$dsn = "mysql:host=$host;dbname=$dbname;charset=utf8";

// Options to handle errors and set PDO modes
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, // Throw exceptions on errors
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, // Default fetch mode to associative array
    PDO::ATTR_EMULATE_PREPARES => false, // Disable emulation of prepared statements
];

// Try to establish a connection to the database
try {
    $pdo = new PDO($dsn, $username, $password, $options);
    // Optionally, you can set the connection to UTF-8 encoding for character compatibility
    $pdo->exec("SET NAMES utf8");
    // Successfully connected; no message displayed
} catch (PDOException $e) {
    // Handle error if connection fails
    echo "Connection failed: " . $e->getMessage();
}
?>
