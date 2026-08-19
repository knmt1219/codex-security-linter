<?php
// Inert benchmark fixture for PHP rules
$cmd = $_GET['cmd'];
system($cmd);
$data = unserialize($_POST['payload']);
?>
