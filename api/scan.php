<?php
// TRICK A4IF - Enterprise Threat Intel API (Vercel Safe Edition)
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

function is_private_ip($ip) {
    return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $url = filter_var(trim($_POST['url']), FILTER_SANITIZE_URL);
    $host = parse_url($url, PHP_URL_HOST) ?: preg_replace('/^www\./', '', $url);

    if (empty($host) || !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid Domain Format']); exit;
    }

    $ip = gethostbyname($host);
    if ($ip === $host) {
        echo json_encode(['status' => 'error', 'message' => 'Domain Unreachable or DNS Dead']); exit;
    }
    if (is_private_ip($ip)) {
        echo json_encode(['status' => 'error', 'message' => 'SSRF Blocked: Internal Target Detected']); exit;
    }

    stream_context_set_default(['http' => ['method' => 'HEAD', 'timeout' => 3]]);
    $headers = @get_headers("https://" . $host, 1) ?: @get_headers("http://" . $host, 1);
    
    $server_type = $headers['Server'] ?? 'Hidden';
    $is_cloudflare = isset($headers['CF-RAY']) || isset($headers['cf-cache-status']);
    if (!$is_cloudflare) {
        $srv_arr = is_array($server_type) ? $server_type : [$server_type];
        foreach($srv_arr as $srv) if (stripos($srv, 'cloudflare') !== false) $is_cloudflare = true;
    }

    $sec_headers = [
        'HSTS' => isset($headers['Strict-Transport-Security']) ? 'Enabled' : 'Missing (Vulnerable)',
        'X-Frame-Options' => $headers['X-Frame-Options'] ?? 'Missing (Clickjacking Possible)',
        'Content-Security-Policy' => $headers['Content-Security-Policy'] ?? 'Missing'
    ];

    $ssl_info = ['issuer' => 'No SSL / Failed', 'valid' => 'N/A'];
    $context = stream_context_create(["ssl" => ["capture_peer_cert" => true, "verify_peer" => false, "verify_peer_name" => false]]);
    $client = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 2, STREAM_CLIENT_CONNECT, $context);
    if ($client) {
        $params = stream_context_get_params($client);
        if (isset($params["options"]["ssl"]["peer_certificate"])) {
            $cert = openssl_x509_parse($params["options"]["ssl"]["peer_certificate"]);
            $ssl_info['issuer'] = $cert['issuer']['O'] ?? $cert['issuer']['CN'] ?? 'Unknown';
            $ssl_info['valid'] = date('Y-m-d', $cert['validTo_time_t']);
        }
    }

    // Vercel Firewall Bypass: Only allowed HTTP/HTTPS ports
    $ports = [80, 443];
    $open_ports = [];
    foreach ($ports as $port) {
        $conn = @fsockopen($ip, $port, $errno, $errstr, 0.2);
        if (is_resource($conn)) { $open_ports[] = $port; fclose($conn); }
    }

    $dns_mx = @dns_get_record($host, DNS_MX) ?: [];
    $dns_txt = @dns_get_record($host, DNS_TXT) ?: [];
    
    $geo = @json_decode(file_get_contents("http://ip-api.com/json/{$ip}?fields=country,city,isp,org"), true);

    echo json_encode([
        'status' => 'success',
        'target' => $host,
        'ip' => $ip,
        'geo' => $geo ?? ['country' => 'Unknown', 'city' => 'Unknown', 'isp' => 'Unknown'],
        'server' => is_array($server_type) ? end($server_type) : $server_type,
        'cloudflare' => $is_cloudflare ? 'Active' : 'Bypassed / Direct',
        'ssl' => $ssl_info,
        'security' => $sec_headers,
        'ports' => $open_ports,
        'dns_mx' => array_column($dns_mx, 'target'),
        'dns_txt' => array_column($dns_txt, 'txt')
    ]);
    exit;
} else {
    echo json_encode(['status' => 'error', 'message' => 'Invalid Request Method']);
}
?>