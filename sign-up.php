<?php
require_once 'zo10a01n/zo1z0aa0501n.php';
session_start(); // Start the session

$errors = [];
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $birth_month = $_POST['birth_month'];
    $birth_year = $_POST['birth_year'];

    // Validate password length
    if (strlen($password) < 8) {
        $errors[] = "Password must be at least 8 characters long.";
    }

    // Check if passwords match
    if ($password !== $confirm_password) {
        $errors[] = "Passwords do not match.";
    }

    // Check for existing username
    $stmt = $pdo->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    if ($stmt->rowCount()) {
        $errors[] = "Username already exists.";
    }

    // Check for existing email
    $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->rowCount()) {
        $errors[] = "Email already exists.";
    }

    // If no errors, proceed to store data
    if (count($errors) === 0) {
        $stmt = $pdo->prepare(
            "INSERT INTO users (username, email, password, birth_month, birth_year) 
             VALUES (?, ?, ?, ?, ?)"
        );

        $stmt->execute([$username, $email, $password, $birth_month, $birth_year]);

        // Get the user ID of the newly created account
        $user_id = $pdo->lastInsertId(); // Fetch the last inserted ID

        // Store user details in session
        $_SESSION['user_id'] = $user_id;  // Log the user in immediately
        $_SESSION['username'] = $username; // Store the username
        $_SESSION['email'] = $email;      // Store the email

        // Redirect to home page
        header('Location: home.php');
        exit();
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign Up Page</title>
    <link href="https://fonts.googleapis.com/css2?family=Open+Sans:wght@400;600&display=swap" rel="stylesheet">
    <style>
        /* General Reset */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        /* Base Styles */
        body {
            font-family: 'Open Sans', sans-serif;
            background-color: royalblue;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            color: white;
        }

        /* Main Container */
        .container {
            background-color: white;
            padding: 30px;
            border-radius: 0px;
            width: 100%;
            max-width: 450px;
            height: 650px;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.2);
        }

        /* Header */
        .signup-form h2 {
            text-align: center;
            margin-bottom: 20px;
            color: royalblue;
            font-weight: bold;
            font-family: 'Open Sans', sans-serif;
        }

        /* Input Fields */
        .input-group {
            position: relative;
            margin-bottom: 20px;
        }

        .input-group input,
        .input-group select {
            width: 100%;
            padding: 10px 5px;
            border: none;
            border-bottom: 2px solid royalblue;
            outline: none;
            font-size: 16px;
            color: black;
            background: none;
            font-family: 'Open Sans', sans-serif;
        }

        .input-group label {
            position: absolute;
            left: 5px;
            top: 10px;
            font-size: 16px;
            color: royalblue;
            pointer-events: none;
            transition: 0.3s ease;
        }

        .input-group input:focus + label,
        .input-group input:valid + label {
            top: -20px;
            font-size: 14px;
            color: royalblue;
        }

        /* Buttons Section */
        .buttons {
            display: flex;
            justify-content: center;
            margin-top: 30px;
        }

        .btn {
            padding: 15px 40px;
            border: none;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: 0.3s ease;
            font-family: 'Open Sans', sans-serif;
            text-align: center;
            color: white;
            background-color: royalblue;
            width: 100%;
            margin: 0 auto;
            border-radius: 0;
        }

        /* Footer Text Styles */
        .footer-text {
            font-size: 14px;
            text-align: center;
            margin-top: 20px;
            color: #555;
            font-family: 'Open Sans', sans-serif;
            line-height: 1.6;
        }

        /* Style for clickable links */
        .footer-text a {
            text-decoration: none;
            color: royalblue;
            font-weight: bold;
        }

        .footer-text a:hover {
            text-decoration: underline;
        }

        /* Error message styles */
        .error-message {
            color: red;
            font-size: 14px;
            text-align: center;
            margin-bottom: 10px;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="signup-form">
            <h2>Sign Up</h2>

            <!-- Display Errors -->
            <?php if (!empty($errors)) : ?>
                <?php foreach ($errors as $error) : ?>
                    <div class="error-message"><?php echo htmlspecialchars($error); ?></div>
                <?php endforeach; ?>
            <?php endif; ?>

            <form action="" method="POST">
                <!-- Username -->
                <div class="input-group">
                    <input type="text" id="username" name="username" required>
                    <label for="username">Username</label>
                </div>

                <!-- Email -->
                <div class="input-group">
                    <input type="email" id="email" name="email" required>
                    <label for="email">Email</label>
                </div>

                <!-- Password -->
                <div class="input-group">
                    <input type="password" id="password" name="password" required>
                    <label for="password">Password</label>
                </div>

                <!-- Confirm Password -->
                <div class="input-group">
                    <input type="password" id="confirm_password" name="confirm_password" required>
                    <label for="confirm_password">Confirm Password</label>
                </div>

                <!-- Birth Month & Year -->
                <div class="input-group">
                    <select id="birth_month" name="birth_month" required>
                        <option value="" disabled selected>Month</option>
                        <?php
                        $months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
                        foreach ($months as $month) {
                            echo "<option value='$month'>$month</option>";
                        }
                        ?>
                    </select>
                    <select id="birth_year" name="birth_year" required>
                        <option value="" disabled selected>Year</option>
                        <?php
                        for ($year = date('Y'); $year >= 1900; $year--) {
                            echo "<option value='$year'>$year</option>";
                        }
                        ?>
                    </select>
                </div>

                <div class="buttons">
                    <button type="submit" class="btn">Sign Up</button>
                </div>

                <div class="footer-text">
                    By creating an account, you agree to the <a href="https://0test01.atwebpages.com/terms_and_conditions.php">Terms and Conditions</a> and <a href="https://example.com/privacy">Privacy Policy</a>.
                </div>
                <div class="footer-text">
                    Melo collects personal data to improve user experience.
                </div>
            </form>
        </div>
    </div>
</body>
</html>
