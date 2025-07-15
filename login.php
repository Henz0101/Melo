<?php
require_once "configuration/config.php";

// Start the session
session_start();

// Buffer output to avoid the header error
ob_start();

// Initialize variables
$email = '';
$password = '';
$error = '';
$success = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? ''); // Trim input to remove accidental spaces
    $password = trim($_POST['password'] ?? '');
    $rememberMe = isset($_POST['remember']);

    if ($email && $password) {
        try {
            $stmt = $pdo->prepare('SELECT * FROM users WHERE email = :email');
            $stmt->execute(['email' => $email]);
            $user = $stmt->fetch();

            // Debugging: Log the database query result
            // Comment out or remove this after you're sure everything works
            // var_dump($user);
            // exit;

            if ($user) {
                // Compare passwords directly
                if ($password === $user['password']) {
                    $success = "Login successful!";

                    // Start user session
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['email'] = $user['email'];
                    $_SESSION['user_id'] = $user['id']; // Store user ID in session

                    // Set a remember me cookie if checked
                    if ($rememberMe) {
                        setcookie('remember_me', $email, time() + (86400 * 30), "/");
                    }

                    // Redirect to home.php
                    header('Location: home.php');
                    exit;
                } else {
                    $error = "Incorrect email or password.";
                }
            } else {
                $error = "No user exists with this email.";
            }
        } catch (Exception $e) {
            $error = "An error occurred: " . $e->getMessage();
        }
    } else {
        $error = "Please fill in all fields.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Page</title>
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
            max-width: 400px;
            height: auto;
            box-shadow: 0 8px 20px rgba(0, 0, 0, 0.2);
        }

        /* Header */
        .login-form h2 {
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

        .input-group input {
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
            font-family: 'Open Sans', sans-serif;
        }

        .input-group input:focus+label,
        .input-group input:valid+label {
            top: -20px;
            font-size: 14px;
            color: royalblue;
        }

        /* Remember Me Section */
        .remember-me {
            display: flex;
            align-items: center;
            font-size: 14px;
            color: royalblue;
            margin-bottom: 20px;
            font-family: 'Open Sans', sans-serif;
        }

        .remember-me input[type="checkbox"] {
            width: 16px;
            height: 16px;
            border: 2px solid royalblue;
            border-radius: 0;
            appearance: none;
            cursor: pointer;
            background-color: white;
            transition: background-color 0.2s ease;
            margin-right: 8px;
        }

        .remember-me input[type="checkbox"]:checked {
            background-color: royalblue;
            border-color: royalblue;
        }

        /* Buttons Section */
        .buttons {
            display: flex;
            justify-content: space-between;
            gap: 10px;
            margin-top: 55px;
        }

        .btn {
            padding: 15px 35px;
            border-radius: 0px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: 0.3s ease;
            font-family: 'Open Sans', sans-serif;
            text-align: center;
            color: white;
        }

        .btn.login {
            background-color: royalblue;
            flex: 1;
            margin-left: auto;
        }

        .btn.signup {
            background-color: white;
            color: royalblue;
            border: 2px solid royalblue;
            flex: 1;
            margin-right: auto;
        }

        /* Message Styles */
        .error {
            color: red;
            text-align: center;
            margin-bottom: 15px;
            font-family: 'Open Sans', sans-serif;
        }

        .success {
            color: green;
            text-align: center;
            margin-bottom: 15px;
            font-family: 'Open Sans', sans-serif;
        }

        /* Forgot Password Section */
        .options .forgot-password {
            text-decoration: none;
            color: royalblue;
            transition: color 0.2s ease;
            font-family: 'Open Sans', sans-serif;
        }

        .options .forgot-password:hover {
            color: darkblue;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="login-form">
            <h2>Login</h2>
            
            <!-- Display success or error -->
            <?php if ($error): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endif; ?>
            <?php if ($success): ?>
                <div class="success"><?php echo htmlspecialchars($success); ?></div>
            <?php endif; ?>

            <form action="login.php" method="POST">
                <div class="input-group">
                    <input type="email" name="email" required>
                    <label for="email">Email</label>
                </div>
                <div class="input-group">
                    <input type="password" name="password" required>
                    <label for="password">Password</label>
                </div>

                <!-- Remember Me Section -->
                <div class="remember-me">
                    <input type="checkbox" name="remember" id="remember">
                    <label for="remember">Remember Me</label>
                </div>

                <!-- Options -->
                <div class="options">
                    <a href="forgot-password.php" class="forgot-password">Forgot Password?</a>
                </div>

                <!-- Login/Signup buttons -->
                <div class="buttons">
                    <button type="button" class="btn signup" onclick="window.location.href='signup.php'">Sign Up</button>
                    <button type="submit" class="btn login">Login</button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>