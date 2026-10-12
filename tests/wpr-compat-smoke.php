<?php
$src = file_get_contents(__DIR__ . "/../ai-crawler-access-for-wordfence.php");
$readme = file_get_contents(__DIR__ . "/../readme.txt");
$checks = array("Version: 1.2.1", "Update URI: https://xn----ctbgf6biedka.xn--p1ai/plugins/ai-crawler-access-for-wordfence/", "WPR_Updates_Client_V2::register");
foreach ($checks as $check) { if (strpos($src, $check) === false) exit(1); }
if (strpos($readme, "Stable tag: 1.2.1") === false) exit(1);
echo "OK\n";
