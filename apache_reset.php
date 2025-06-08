<?php
if (function_exists('opcache_reset')) {
    opcache_reset();
    echo "OPcache resetado com sucesso!";
} else {
    echo "OPcache não está habilitado ou a função opcache_reset não existe.";
}
?>