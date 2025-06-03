<?php
// Página para cliente acompanhar status do pedido
require_once 'includes/functions.php';

$order_id = $_GET['id'];
$order = getOrderStatus($order_id);
?>