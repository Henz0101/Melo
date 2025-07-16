<?php
// src/handle_forgot_password.php

require_once 'zo10a01n/zo1z0aa0501n.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $newPassword = trim($_POST['new_password'] ?? '');

    if (empty($email) || empty($newPassword)) {
        header("Location: ../public/forgot_password.php?status=error");
        exit;
    }

    try {
        $stmt = $pdo->prepare("SELECT * FROM users WHERE email = :email");
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            header("Location: ../public/forgot_password.php?status=not_found");
            exit;
        }

        $hashedPassword = password_hash($newPassword, PASSWORD_DEFAULT);

        $updateStmt = $pdo->prepare("UPDATE users SET password = :password WHERE email = :email");
        $updateStmt->execute([
            'password' => $hashedPassword,
            'email' => $email
        ]);

        header("Location: ../public/forgot_password.php?status=success");
        exit;
    } catch (PDOException $e) {
        header("Location: ../public/forgot_password.php?status=error");
        exit;
    }
} else {
    header("Location: ../public/forgot_password.php");
    exit;
}
