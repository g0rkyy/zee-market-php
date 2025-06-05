<?php
// Configurações de segurança reais
define('ENCRYPTION_KEY', hash('sha256', 'sua_chave_secreta_unica'));
define('HASH_SALT', 'salt_aleatorio_complexo_2024');

// Rate limiting
$_SESSION['api_calls'] = $_SESSION['api_calls'] ?? [];
$_SESSION['last_request'] = $_SESSION['last_request'] ?? 0;

// Headers de segurança
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
?>