<?php

session_start();

// Database connection details
$host = 'db'; // Or your database host
$db   = 'di_internet_technologies_project'; // Your database name
$user = 'webuser'; // Your database user
$pass = 'webpass'; // Your database password


// Create connection
$conn = new mysqli($host, $user, $pass, $db);


// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Set charset to utf8mb4 for proper Greek character handling
$conn->set_charset("utf8mb4");

// Initialize variables for messages and form stickiness
$registration_error = '';
$registration_success = '';
$just_registered_username = null; // Used to prefill login form after successful registration

// --- Registration Logic ---
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['register_submit'])) {
    // Sanitize and retrieve form data
    $first_name = trim($_POST["first_name"]);
    $last_name = trim($_POST["last_name"]);
    $username_reg = trim($_POST["username_reg"]);
    $email_reg = trim($_POST["email_reg"]);
    $password_reg = $_POST["password_reg"]; // Password (will be hashed)
    $confirm_password = $_POST["confirm_password"];

    // Basic validation
    if (empty($first_name) || empty($last_name) || empty($username_reg) || empty($email_reg) || empty($password_reg)) {
        $registration_error = "Όλα τα πεδία είναι υποχρεωτικά.";
    } elseif (!filter_var($email_reg, FILTER_VALIDATE_EMAIL)) {
        $registration_error = "Μη έγκυρη διεύθυνση email.";
    } elseif (strlen($password_reg) < 8) {
        $registration_error = "Ο κωδικός πρόσβασης πρέπει να έχει τουλάχιστον 8 χαρακτήρες.";
    } elseif ($password_reg !== $confirm_password) {
        $registration_error = "Οι κωδικοί πρόσβασης δεν ταιριάζουν.";
    } else {
        // Check if username or email already exists
        $stmt_check = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
        $stmt_check->bind_param("ss", $username_reg, $email_reg);
        $stmt_check->execute();
        $stmt_check->store_result();

        if ($stmt_check->num_rows > 0) {
            $registration_error = "Αυτό το όνομα χρήστη ή το email χρησιμοποιείται ήδη.";
        } else {
            // Hash the password
            $hashed_password_reg = password_hash($password_reg, PASSWORD_DEFAULT);

            // Prepare and execute insert statement
            $stmt_insert = $conn->prepare("INSERT INTO users (first_name, last_name, username, password, email) VALUES (?, ?, ?, ?, ?)");
            $stmt_insert->bind_param("sssss", $first_name, $last_name, $username_reg, $hashed_password_reg, $email_reg);

            if ($stmt_insert->execute()) {
                $registration_success = "Η εγγραφή ολοκληρώθηκε με επιτυχία! Μπορείτε τώρα να συνδεθείτε.";
                $just_registered_username = $username_reg; // For prefilling login form
                // Clear POST data to prevent re-submission and clear form fields on success
                $_POST = array();
            } else {
                $registration_error = "Σφάλμα κατά την εγγραφή: " . $stmt_insert->error;
            }
            $stmt_insert->close();
        }
        $stmt_check->close();
    }
}

// --- Login Logic ---
$login_error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login_submit'])) {
    $username_login = trim($_POST['username_login']);
    $password_login = $_POST['password_login'];

    if (empty($username_login) || empty($password_login)) {
        $login_error = "Το όνομα χρήστη και ο κωδικός είναι υποχρεωτικά.";
    } else {
        $stmt_login = $conn->prepare("SELECT id, password FROM users WHERE username = ?");
        if (!$stmt_login) {
             $login_error = "Σφάλμα συστήματος. Παρακαλώ δοκιμάστε αργότερα. (DB Error: Prepare failed)";
        } else {
            $stmt_login->bind_param("s", $username_login);
            $stmt_login->execute();
            $stmt_login->store_result();

            if ($stmt_login->num_rows === 1) {
                $stmt_login->bind_result($user_id, $hashed_password_db);
                $stmt_login->fetch();

                if (password_verify($password_login, $hashed_password_db)) {
                    // Login successful
                    $_SESSION['user_id'] = $user_id;
                    // Redirect to profile page (replace with your actual profile page)
                    header("Location: profile.php");
                    exit();
                } else {
                    $login_error = "Λάθος όνομα χρήστη ή κωδικός πρόσβασης.";
                }
            } else {
                $login_error = "Λάθος όνομα χρήστη ή κωδικός πρόσβασης.";
            }
            $stmt_login->close();
        }
    }
}

// Close connection (optional here, as PHP closes it at script end)
// $conn->close();
?>
<!DOCTYPE html>
<html lang="el">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Σύνδεση / Εγγραφή - Πλατφόρμα Λιστών</title>
    <link rel="icon" type="image/x-icon" href="./images/favicon.png">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* Reset and Global Styles */
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Poppins', Arial, Helvetica, sans-serif;
            background-color: #1a202c; /* Dark theme background */
            color: #e2e8f0; /* Dark theme text color */
            transition: background-color 0.3s, color 0.3s;
            display: flex;
            flex-direction: column;
            height: 100vh; 
            overflow: hidden; 
            line-height: 1.6;
        }

        /* Top Navigation Bar Styles */
        .topnav {
            overflow: hidden;
            background-color: #2d3748;
            position: relative;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 60px; 
            padding: 0 20px; 
            box-shadow: 0 2px 4px rgba(0,0,0,0.1); 
            width: 100%;
            flex-shrink: 0; 
        }

        .topnav .brand {
            position: absolute;
            left: 20px;
            top: 50%;
            transform: translateY(-50%);
            color: #8db1da;
            font-size: 24px;
            font-weight: 600;
        }

        .nav-links-group {
            display: flex;
            align-items: center;
        }

        .topnav a:not(.login-signup-link) {
            color: #f2f2f2;
            text-align: center;
            padding: 18px 22px;
            text-decoration: none;
            font-size: 17px;
            font-weight: 400;
            transition: background-color 0.3s, color 0.3s;
            display: inline-block;
        }

        .topnav a:not(.login-signup-link):hover {
            background-color: #4a5568;
            color: white;
        }

        .topnav a.active:not(.login-signup-link) {
            background-color: #4a5568;
            color: white;
            font-weight: 600;
        }
        
        .topnav-right-items {
        }

        .login-signup-link {
            position: absolute;
            right: 70px;
            top: 50%;
            transform: translateY(-50%);
            padding: 10px 18px;
            border-radius: 8px;
            background-color: #4a5568;
            color: #e2e8f0;
            text-decoration: none;
            font-size: 15px;
            font-weight: 500;
            transition: background-color 0.3s, color 0.3s, transform 0.2s;
            white-space: nowrap;
        }

        .login-signup-link:hover {
            background-color: #615bb1;
            color: white;
            transform: translateY(-50%) translateY(-2px);
        }
        
        .login-signup-link.active {
             background-color: #615bb1;
             color: white;
        }

        #theme-toggle {
            position: absolute;
            right: 20px;
            top: 50%;
            transform: translateY(-50%);
            background: none;
            border: none;
            color: #8db1da;
            font-size: 22px;
            cursor: pointer;
            padding: 5px;
            line-height: 1;
            transition: color 0.3s, transform 0.2s;
        }

        #theme-toggle:hover {
            color: #f2f2f2;
            transform: scale(1.1);
        }

        ::selection {
            background: #615bb1;
            color: #fff;
        }

        /* Main Content Area */
        .center-container {
            display: flex;
            justify-content: center;
            align-items: center; 
            flex-grow: 1;
            padding: 20px 20px; 
            width: 100%;
            overflow-y: auto; 
        }

        .wrapper { 
            overflow: visible; 
            max-width: 390px;
            width: 100%;
            background: #2d3748;
            padding: 20px; 
            border-radius: 15px;
            box-shadow: 0px 10px 15px rgba(0, 0, 0, 0.15); 
            color: #e2e8f0;
        }

        .wrapper .title-text {
            display: flex;
            width: 200%; 
        }

        .wrapper .title {
            width: 50%; 
            font-size: 28px; 
            font-weight: 600;
            text-align: center;
            color: #e2e8f0; 
            margin-bottom: 5px; 
            opacity: 0; /* Αρχικά αόρατος */
            transition: margin-left 0.6s cubic-bezier(0.68, -0.55, 0.265, 1.55),
                        opacity 0.4s ease-in-out; /* Αφαιρέθηκε η καθυστέρηση από την opacity */
        }
        
        .wrapper .title.title-visible {
            opacity: 1; /* Κλάση για να γίνει ορατός ο τίτλος */
        }

        .wrapper .slide-controls {
            position: relative;
            display: flex;
            height: 45px; 
            width: 100%;
            overflow: hidden;
            margin: 15px 0 10px 0; 
            justify-content: space-between;
            border: 1px solid #4a5568;
            border-radius: 12px; 
        }

        .slide-controls .slide {
            height: 100%;
            color: #cbd5e0;
            font-size: 17px; 
            font-weight: 500;
            text-align: center;
            line-height: 43px; 
            cursor: pointer;
            z-index: 1;
            transition: all 0.6s ease;
            width: 50%;
            position: relative;
        }

        .slide-controls .slider-tab {
            position: absolute;
            height: 100%;
            width: 50%;
            left: 0;
            z-index: 0;
            border-radius: 12px; 
            background: #615bb1;
            transition: all 0.6s cubic-bezier(0.68, -0.55, 0.265, 1.55);
        }

        input[type="radio"] {
            display: none;
        }

        #signup:checked ~ .slider-tab { left: 50%; }
        #signup:checked ~ label.signup { color: #fff; cursor: default; user-select: none; }
        #signup:checked ~ label.login { color: #cbd5e0; }
        #login:checked ~ label.signup { color: #cbd5e0; }
        #login:checked ~ label.login { color: #fff; cursor: default; user-select: none; }

        .wrapper .form-container { width: 100%; overflow: hidden; }
        .form-container .form-inner { display: flex; width: 200%; }
        .form-container .form-inner form { width: 50%; transition: all 0.6s cubic-bezier(0.68, -0.55, 0.265, 1.55); }

        .form-inner form .field { 
            height: 40px; 
            width: 100%; 
            margin-top: 10px; 
            position: relative; 
        }
        .form-inner form .field input {
            height: 100%; width: 100%; outline: none; padding-left: 15px; padding-right: 15px;
            border-radius: 10px; 
            border: 1px solid #4a5568;
            background-color: #2d3748;
            color: #e2e8f0;
            font-size: 15px; 
            transition: all 0.3s ease;
        }
        .form-inner form .field input:focus { border-color: #615bb1; }
        .form-inner form .field input::placeholder { color: #a0aec0; transition: all 0.3s ease; }
        form .field input:focus::placeholder { color: #615bb1; }

        .form-inner form .signup-link { 
            text-align: center; 
            margin-top: 15px; 
            font-size: 14px; 
        }
        .form-inner form .signup-link a { color: #8db1da;text-decoration: none; }
        .form-inner form .signup-link a:hover { text-decoration: underline; }

        form .btn { 
            height: 40px; 
            width: 100%; 
            border-radius: 10px; 
            position: relative; 
            overflow: hidden; 
            margin-top: 15px; 
        }
        form .btn .btn-layer { height: 100%; width: 300%; position: absolute; left: -100%; background: #615bb1;  border-radius: 10px; transition: all 0.4s ease; }
        form .btn:hover .btn-layer { left: 0; }
        form .btn input[type="submit"] {
            height: 100%; width: 100%; z-index: 1; position: relative; background: none; border: none;
            color: #fff; padding-left: 0; border-radius: 10px; font-size: 18px; font-weight: 500; cursor: pointer;
        }

        .validation-message {
            font-size: 13px; 
            margin-top: 8px; 
            min-height: 1.2em;
            text-align: center;
        }
        .validation-message.error { color: #f56565;}
        .validation-message.success { color: #38a169;}

        .form-inner form .field input.invalid { border-color: #f56565;}

        hr {
            border: 0;
            height: 1px;
            width: 100%;
            background-color: #4a5568;
            margin-top: 20px; 
            margin-bottom: 0;
            flex-shrink: 0;
        }
        .footer {
            font-size: 0.85em; 
            width: 100%;
            color: #a0aec0;
            text-align: center;
            text-decoration: none;
            padding: 15px 0; 
            flex-shrink: 0;
        }

        /* --- Light Theme Styles --- */
        body.light-theme {
            background-color: #f8f9fa;
            color: #212529;
        }
        body.light-theme .topnav {
            background-color: #e9ecef;
            box-shadow: 0 2px 4px rgba(0,0,0,0.05);
        }
        body.light-theme .topnav .brand { color: #0056b3; }
        body.light-theme .topnav a:not(.login-signup-link) { color: #343a40; }
        body.light-theme .topnav a:not(.login-signup-link):hover { background-color: #007bff; color: white; }
        body.light-theme .topnav a.active:not(.login-signup-link) { background-color: #007bff; color: white; }

        body.light-theme .login-signup-link {
            background-color: #007bff;
            color: white;
        }
        body.light-theme .login-signup-link:hover {
            background-color: #0056b3;
        }
        body.light-theme .login-signup-link.active {
             background-color: #0056b3;
             color: white;
        }

        body.light-theme #theme-toggle { color: #0056b3; }
        body.light-theme #theme-toggle:hover {
            color: #007bff;
            transform: scale(1.1);
        }

        body.light-theme ::selection { background: #007bff; color: #fff; }
        
        body.light-theme .wrapper {
            background: #ffffff;
            box-shadow: 0px 10px 15px rgba(0, 0, 0, 0.08); 
            color: #212529;
        }

        body.light-theme .wrapper .title { 
            color: #212529; 
            opacity: 0; 
            transition: margin-left 0.6s cubic-bezier(0.68, -0.55, 0.265, 1.55),
                        opacity 0.4s ease-in-out; 
        }
        body.light-theme .wrapper .title.title-visible {
            opacity: 1; 
        }

        body.light-theme .slide-controls { border: 1px solid #dee2e6; }
        body.light-theme .slide-controls .slide { color: #495057; }
        body.light-theme #signup:checked ~ label.signup,
        body.light-theme #login:checked ~ label.login { color: #fff; }
        body.light-theme #signup:checked ~ label.login,
        body.light-theme #login:checked ~ label.signup { color: #495057; }

        body.light-theme .slide-controls .slider-tab { background: #007bff; }
        body.light-theme .form-inner form .field input {
            border: 1px solid #ced4da;
            background-color: #ffffff;
            color: #495057;
        }
        body.light-theme .form-inner form .field input:focus { border-color: #80bdff; }
        body.light-theme .form-inner form .field input::placeholder { color: #6c757d; }
        body.light-theme form .field input:focus::placeholder { color: #007bff; }
        body.light-theme .form-inner form .signup-link a { color: #007bff; }
        body.light-theme form .btn .btn-layer { background: #007bff; }

        body.light-theme .validation-message.error { color: #dc3545; }
        body.light-theme .validation-message.success { color: #198754; }
        body.light-theme .form-inner form .field input.invalid { border-color: #dc3545; }

        body.light-theme hr { background-color: #dee2e6; }
        body.light-theme .footer { color: #6c757d; }

        /* Responsive Styles - Consistent with other pages */
        @media (max-width: 768px) {
            .topnav .brand { font-size: 20px; }
            .topnav a:not(.login-signup-link) { padding: 15px 10px; font-size: 15px; }
            .login-signup-link {
                padding: 8px 12px; font-size: 14px;
                right: 60px;
            }
            #theme-toggle {
                font-size: 20px;
                right: 15px;
            }
            .center-container {
                padding: 15px 10px; 
            }
            .wrapper {
                padding: 15px; 
            }
             .wrapper .title {
                font-size: 24px; 
            }
            .slide-controls .slide {
                font-size: 16px; 
            }
            .form-inner form .field input, 
            form .btn input[type="submit"] {
                font-size: 14px; 
            }
            .form-inner form .signup-link {
                font-size: 13px;
            }
        }

        @media (max-width: 500px) {
            .topnav {
                justify-content: space-between;
            }
            .topnav .brand {
                position: static;
                transform: none;
                padding: 10px 0;
                font-size: 18px; 
            }
            .nav-links-group {
                display: none;
            }
            .topnav-right-items {
                position: static;
                transform: none;
                display: flex;
                align-items: center;
            }
            .login-signup-link {
                position: static;
                transform: none;
                margin-left: 8px; 
                padding: 7px 10px; 
                font-size: 13px; 
            }
            #theme-toggle {
                position: static;
                transform: none;
                font-size: 18px; 
            }
            .center-container {
                padding: 10px 5px; 
            }
            .wrapper {
                padding: 10px; 
            }
            .wrapper .title {
                font-size: 22px; 
            }
            .wrapper .slide-controls {
                height: 40px;
                margin: 10px 0 8px 0;
            }
            .slide-controls .slide {
                font-size: 14px; 
                line-height: 38px;
            }
            .form-inner form .field {
                height: 38px;
                margin-top: 8px;
            }
            .form-inner form .field input {
                font-size: 14px;
            }
            form .btn {
                height: 38px;
                margin-top: 10px;
            }
             form .btn input[type="submit"] {
                font-size: 16px;
            }
            .form-inner form .signup-link {
                margin-top: 10px;
                font-size: 12px;
            }
            .validation-message {
                font-size: 12px;
                margin-top: 5px;
            }
        }

    </style>
</head>
<body>
    <div class="topnav">
        <span class="brand">Πλατφόρμα Λιστών</span>
        <div class="nav-links-group">
            <a href="index.html">Αρχική</a>
            <a href="goal_sign_up.html">Σκοπός & Εγγραφή</a>
            <a href="help.html">Βοήθεια</a>
        </div>
        <div class="topnav-right-items">
            <a href="sign_up_log_in.php" class="login-signup-link active">Σύνδεση/Εγγραφή</a>
            <button id="theme-toggle" title="Εναλλαγή θέματος">
                <i class="fa fa-sun-o" aria-hidden="true"></i>
            </button>
        </div>
    </div>

    <div class="center-container">
        <div class="wrapper">
            <div class="title-text">
                <div class="title login">Σύνδεση</div>
                <div class="title signup">Εγγραφή</div>
            </div>

            <?php if (!empty($registration_success)) : ?>
                <div class="validation-message success" style="margin-bottom: 10px; text-align:center;">
                    <?= htmlspecialchars($registration_success) ?>
                </div>
            <?php endif; ?>

            <div class="form-container">
                <div class="slide-controls">
                    <?php
                        $login_active = true; 
                        if (isset($_POST['register_submit']) && !empty($registration_error)) {
                            $login_active = false;
                        } elseif (isset($_POST['login_submit']) && !empty($login_error)) { 
                            $login_active = true;
                        } elseif (!empty($registration_success)) {
                            $login_active = true;
                        }
                    ?>
                    <input type="radio" name="slide" id="login" <?php if ($login_active) echo 'checked'; ?>>
                    <input type="radio" name="slide" id="signup" <?php if (!$login_active) echo 'checked'; ?>>
                    <label for="login" class="slide login">Σύνδεση</label>
                    <label for="signup" class="slide signup">Εγγραφή</label>
                    <div class="slider-tab"></div>
                </div>
                <div class="form-inner">
                    <form action="sign_up_log_in.php" method="POST" class="login">
                        <?php if (!empty($login_error) && $login_active) : ?>
                            <div class="validation-message error"><?= htmlspecialchars($login_error) ?></div>
                        <?php endif; ?>
                        <div class="field">
                            <input type="text" name="username_login" placeholder="Όνομα χρήστη" required
                                   value="<?= $just_registered_username ? htmlspecialchars($just_registered_username) : (isset($_POST['username_login']) ? htmlspecialchars($_POST['username_login']) : '') ?>">
                        </div>
                        <div class="field">
                            <input type="password" name="password_login" placeholder="Κωδικός Πρόσβασης" required>
                        </div>
                        <div class="field btn">
                            <div class="btn-layer"></div>
                            <input type="submit" name="login_submit" value="Σύνδεση">
                        </div>
                        <div class="signup-link">Δεν είσαι μέλος; <a href="#" id="switchToSignupLink">Εγγραφή τώρα</a></div>
                    </form>

                    <form action="sign_up_log_in.php" method="POST" class="signup" id="signupForm">
                        <?php if (!empty($registration_error) && !$login_active) : ?>
                            <div class="validation-message error"><?= htmlspecialchars($registration_error) ?></div>
                        <?php endif; ?>
                        <div class="field">
                            <input type="text" name="first_name" placeholder="Όνομα" required value="<?= isset($_POST['first_name']) && empty($registration_success) ? htmlspecialchars($_POST['first_name']) : '' ?>">
                        </div>
                        <div class="field">
                            <input type="text" name="last_name" placeholder="Επώνυμο" required value="<?= isset($_POST['last_name']) && empty($registration_success) ? htmlspecialchars($_POST['last_name']) : '' ?>">
                        </div>
                        <div class="field">
                             <input type="text" name="username_reg" placeholder="Όνομα χρήστη" required value="<?= isset($_POST['username_reg']) && empty($registration_success) ? htmlspecialchars($_POST['username_reg']) : '' ?>">
                        </div>
                        <div class="field">
                            <input type="email" name="email_reg" placeholder="Διεύθυνση Email" id="signupEmail" required value="<?= isset($_POST['email_reg']) && empty($registration_success) ? htmlspecialchars($_POST['email_reg']) : '' ?>">
                        </div>
                        <div class="field">
                            <input type="password" name="password_reg" placeholder="Κωδικός Πρόσβασης" id="signupPassword" required>
                        </div>
                        <div class="field">
                            <input type="password" name="confirm_password" placeholder="Επιβεβαίωση Κωδικού" id="signupConfirmPassword" required>
                        </div>
                        <div class="validation-message" id="signupValidationMessageJS"></div>
                        <div class="field btn">
                            <div class="btn-layer"></div>
                            <input type="submit" name="register_submit" value="Εγγραφή">
                        </div>
                        <div class="signup-link"> 
                            Είστε ήδη μέλος; <a href="#" id="switchToLoginLink">Σύνδεση τώρα</a>
                        </div>
                    </form>
                </div>
            </div>
        </div>
    </div>

    <hr>
    <footer class="footer">
        Τεχνολογίες Διαδικτύου - Εργασία 2025 - Ιόνιο Πανεπιστήμιο, Τμήμα Πληροφορικής
    </footer>

    <script>
        // --- Form Slider Logic (Login/Signup Tabs) ---
        const loginForm = document.querySelector("form.login");
        const switchToSignupLink = document.getElementById("switchToSignupLink");
        const switchToLoginLink = document.getElementById("switchToLoginLink");
        const loginTitle = document.querySelector(".title.login"); 
        const signupTitle = document.querySelector(".title.signup");

        const loginRadio = document.getElementById('login');
        const signupRadio = document.getElementById('signup');

        // Function to update display based on which radio is checked (for transitions)
        function updateDisplayForSwitch() {
            // Determine which title should start fading out
            if (loginRadio.checked) { // Login is now active, Signup was potentially active
                if (signupTitle) signupTitle.classList.remove('title-visible');
            } else { // Signup is now active, Login was potentially active
                if (loginTitle) loginTitle.classList.remove('title-visible');
            }

            // After a brief moment (to let the fade-out start), perform slide and fade-in
            setTimeout(() => {
                if (signupRadio.checked) {
                    loginForm.style.marginLeft = "-50%";
                    if (loginTitle) loginTitle.style.marginLeft = "-50%"; // Slide out old title
                    if (signupTitle) {
                        signupTitle.style.marginLeft = "0%"; // Ensure correct position
                        signupTitle.classList.add('title-visible'); // Fade in new title
                    }
                } else { // loginRadio.checked
                    loginForm.style.marginLeft = "0%";
                    // Ensure signup title is reset if it was slid (though it's usually hidden)
                    if (signupTitle) signupTitle.style.marginLeft = "0%"; 
                    if (loginTitle) {
                        loginTitle.style.marginLeft = "0%"; // Ensure correct position
                        loginTitle.classList.add('title-visible'); // Fade in new title
                    }
                }
            }, 50); // Small delay for visual sequencing of fade-out then slide/fade-in.
        }

        // Initial setup on page load for immediate visibility
        function setInitialFormDisplay() {
            if (signupRadio.checked) { // If PHP decided signup is active
                loginForm.style.marginLeft = "-50%";
                if (loginTitle) loginTitle.style.marginLeft = "-50%"; // Position it as slid out
                if (signupTitle) {
                    signupTitle.style.marginLeft = "0%"; 
                    signupTitle.classList.add('title-visible'); // Show immediately
                }
            } else { // Login is active by default or by PHP
                loginForm.style.marginLeft = "0%"; 
                if (loginTitle) {
                    loginTitle.style.marginLeft = "0%"; 
                    loginTitle.classList.add('title-visible'); // Show immediately
                }
                // Ensure signup title is correctly positioned even if hidden initially
                if (signupTitle) signupTitle.style.marginLeft = "0%";
            }
        }

        setInitialFormDisplay(); // Call for page load

        // Listen to changes on radio buttons for subsequent switches
        loginRadio.addEventListener('change', function() {
            if (this.checked) {
                updateDisplayForSwitch();
            }
        });
        signupRadio.addEventListener('change', function() {
            if (this.checked) {
                updateDisplayForSwitch();
            }
        });

        // Links will trigger radio change, which then calls updateDisplayForSwitch
        if (switchToSignupLink) {
            switchToSignupLink.addEventListener('click', function(e) {
                e.preventDefault();
                if (!signupRadio.checked) {
                    signupRadio.checked = true;
                    // Manually dispatch change event for browsers that might not do it automatically
                    // on programmatic 'checked = true'
                    signupRadio.dispatchEvent(new Event('change', { bubbles: true }));
                }
            });
        }
        
        if (switchToLoginLink) {
            switchToLoginLink.addEventListener('click', function(e) {
                e.preventDefault();
                if (!loginRadio.checked) {
                    loginRadio.checked = true;
                    loginRadio.dispatchEvent(new Event('change', { bubbles: true }));
                }
            });
        }


        // --- Theme Toggle Logic ---
        const themeToggleBtn = document.getElementById('theme-toggle');
        const body = document.body;
        const themeIcon = themeToggleBtn.querySelector('i');

        function setTheme(theme) {
            body.classList.remove('light-theme', 'dark-theme');
            themeIcon.classList.remove('fa-sun-o', 'fa-moon-o');

            if (theme === 'light') {
                body.classList.add('light-theme');
                themeIcon.classList.add('fa-moon-o');
                localStorage.setItem('theme', 'light');
                themeToggleBtn.title = "Εναλλαγή σε σκούρο θέμα";
            } else {
                body.classList.add('dark-theme'); // Default to dark if anything else
                themeIcon.classList.add('fa-sun-o');
                localStorage.setItem('theme', 'dark');
                themeToggleBtn.title = "Εναλλαγή σε ανοιχτό θέμα";
            }
        }

        const currentTheme = localStorage.getItem('theme');
        setTheme(currentTheme || 'dark'); // Default to dark if no theme saved

        themeToggleBtn.addEventListener('click', () => {
            const newTheme = body.classList.contains('light-theme') ? 'dark' : 'light';
            setTheme(newTheme);
        });

        // --- Client-side Signup Form Validation ---
        const signupFormElement = document.getElementById('signupForm');
        const emailInput = document.getElementById('signupEmail');
        const passwordInput = document.getElementById('signupPassword');
        const confirmPasswordInput = document.getElementById('signupConfirmPassword');
        const validationMessageJSElement = document.getElementById('signupValidationMessageJS');

        if (signupFormElement) {
            signupFormElement.addEventListener('submit', function(event) {
                if(validationMessageJSElement) {
                    validationMessageJSElement.textContent = '';
                    validationMessageJSElement.className = 'validation-message';
                }
                if(emailInput) emailInput.classList.remove('invalid');
                if(passwordInput) passwordInput.classList.remove('invalid');
                if(confirmPasswordInput) confirmPasswordInput.classList.remove('invalid');

                const email = emailInput ? emailInput.value.trim() : '';
                const password = passwordInput ? passwordInput.value : '';
                const confirmPassword = confirmPasswordInput ? confirmPasswordInput.value : '';

                let isValid = true;
                let messages = [];

                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (emailInput && !emailRegex.test(email)) {
                    messages.push('Η διεύθυνση email δεν έχει έγκυρη μορφή.');
                    emailInput.classList.add('invalid');
                    isValid = false;
                }

                if (passwordInput && password.length < 8) {
                    messages.push('Ο κωδικός πρόσβασης πρέπει να έχει τουλάχιστον 8 χαρακτήρες.');
                    passwordInput.classList.add('invalid');
                    isValid = false;
                }

                if (passwordInput && confirmPasswordInput && password !== confirmPassword) {
                    messages.push('Οι κωδικοί πρόσβασης δεν ταιριάζουν.');
                    confirmPasswordInput.classList.add('invalid');
                    isValid = false;
                }

                if (!isValid) {
                    event.preventDefault();
                    if(validationMessageJSElement) {
                        validationMessageJSElement.textContent = messages.join(' ');
                        validationMessageJSElement.classList.add('error');
                    }
                }
            });

            [emailInput, passwordInput, confirmPasswordInput].forEach(input => {
                 if(input) {
                     input.addEventListener('input', () => {
                         if (input.classList.contains('invalid')) {
                             input.classList.remove('invalid');
                         }
                         if (validationMessageJSElement && validationMessageJSElement.classList.contains('error')) {
                              validationMessageJSElement.textContent = '';
                              validationMessageJSElement.className = 'validation-message';
                          }
                     });
                 }
            });
        }
    </script>
</body>
</html>