<?php
// Zee-Market - Gerador de Endereços de Depósito Seguro (Modelo HD com xpub)
// Versão 2.0 - Hardened

session_start();

// Carrega todas as nossas dependências do Composer e arquivos de configuração.
require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/functions.php';
require_once __DIR__ . '/includes/SecurityLogger.php';

// Importa as classes necessárias da biblioteca BitWasp.
use BitWasp\Bitcoin\Bitcoin;
use BitWasp\Bitcoin\Network\NetworkFactory;
use BitWasp\Bitcoin\Key\Deterministic\HdPrefix\GlobalPrefixConfig;
use BitWasp\Bitcoin\Key\Deterministic\HdPrefix\NetworkConfig;
use BitWasp\Bitcoin\Key\KeyToScript\Factory\P2pkhScriptDataFactory;
use BitWasp\Bitcoin\Serializer\Key\HierarchicalKey\Base58ExtendedKeySerializer;
use BitWasp\Bitcoin\Serializer\Key\HierarchicalKey\ExtendedKeySerializer;

// Garante que o usuário está logado.
if (!isset($_SESSION['user_id'])) {
    // Se não estiver logado, não há ação a ser feita. Pode redirecionar ou mostrar um erro.
    header("Location: login.php");
    exit();
}

$user_id = $_SESSION['user_id'];
$securityLogger = new SecurityLogger();

/**
 * Gera um novo endereço de depósito único para um usuário usando a xpub.
 * Não há manuseio de chaves privadas neste processo.
 *
 * @param int $user_id O ID do usuário para o qual gerar o endereço.
 * @param mysqli $mysqli A conexão com o banco de dados.
 * @return string O novo endereço de Bitcoin gerado.
 * @throws Exception Em caso de falha.
 */
function gerarNovoEnderecoParaUsuario($user_id, $mysqli) {
    
    // Verifica se a xpub foi configurada. Sem ela, o sistema não pode funcionar.
    if (!defined('MASTER_PUBLIC_KEY') || empty(MASTER_PUBLIC_KEY)) {
        throw new Exception("FATAL: Master Public Key (xpub) não está configurada.");
    }

    // Configura a rede Bitcoin.
    $bitcoin = NetworkFactory::bitcoin();
    $adapter = Bitcoin::getEcAdapter();
    
    // Prepara o serializador para interpretar nossa chave xpub.
    $serializer = new Base58ExtendedKeySerializer(new ExtendedKeySerializer($adapter));
    $master_key = $serializer->parse($bitcoin, MASTER_PUBLIC_KEY);

    // Define um caminho de derivação único e não sequencial para o usuário.
    // Usar o user_id diretamente (m/0/user_id) funciona, mas para privacidade extra,
    // podemos usar um hash do user_id. Aqui, usaremos o user_id para simplicidade.
    // O caminho "0/{$user_id}" significa que estamos usando a cadeia 0 (externa/recebimento)
    // e o índice correspondente ao ID do usuário.
    $caminho_derivacao = "0/{$user_id}";
    $derived_key = $master_key->derivePath($caminho_derivacao);
    
    // Gera o endereço no formato P2PKH (Pay-to-Pubkey-Hash), o mais comum (endereços que começam com "1").
    $address = new \BitWasp\Bitcoin\Address\PayToPubKeyHashAddress($derived_key->getPublicKey()->getPubKeyHash());
    $novo_endereco_btc = $address->getAddress();

    // Atualiza o banco de dados com o novo endereço do usuário.
    $stmt = $mysqli->prepare("UPDATE users SET btc_address = ? WHERE id = ?");
    $stmt->bind_param("si", $novo_endereco_btc, $user_id);
    if (!$stmt->execute()) {
        throw new Exception("Falha ao salvar o novo endereço no banco de dados.");
    }
    
    return $novo_endereco_btc;
}

// --- Lógica Principal do Script ---
try {
    // Chamamos a função para gerar e salvar o endereço.
    $endereco_gerado = gerarNovoEnderecoParaUsuario($user_id, $mysqli);
    
    $securityLogger->logSecurityEvent('Novo Endereço de Depósito Gerado', $user_id, 'INFO', $_SERVER['REMOTE_ADDR']);

    // Redireciona o usuário para o painel, onde o novo endereço será exibido.
    header("Location: dashboard.php?success=" . urlencode("Um novo endereço de depósito foi gerado para você."));
    exit();

} catch (Exception $e) {
    // Em caso de qualquer erro, logamos e informamos o usuário.
    $securityLogger->logSecurityEvent('Falha ao Gerar Endereço de Depósito', $user_id, 'CRITICAL', $_SERVER['REMOTE_ADDR'], $e->getMessage());

    header("Location: dashboard.php?error=" . urlencode("Não foi possível gerar um novo endereço. Contate o suporte."));
    exit();
}
?>