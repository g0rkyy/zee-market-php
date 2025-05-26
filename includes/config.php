<?php
$host = "localhost";
$user = "root";
$pass = ""; 
$db = "zee_market"; // Verifique se este é o nome correto do banco

$conn = new mysqli($host, $user, $pass, $db);

if ($conn->connect_error) {
    die("Falha na conexão: " . $conn->connect_error);
}
?> 