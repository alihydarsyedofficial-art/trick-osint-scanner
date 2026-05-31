<?php
// TRICK A4IF - Phishing Report Backend API
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $url = filter_var(trim($_POST['url']), FILTER_SANITIZE_URL);
    $host = parse_url($url, PHP_URL_HOST) ?: preg_replace('/^www\./', '', $url);

    if (empty($host) || !filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid Domain']); exit;
    }

    $ip = gethostbyname($host);
    if ($ip === $host) {
        echo json_encode(['status' => 'error', 'message' => 'Domain Offline']); exit;
    }

    // Get ISP and Location
    $geo = @json_decode(file_get_contents("http://ip-api.com/json/{$ip}?fields=country,isp,org"), true);
    $isp = $geo['isp'] ?? 'Unknown ISP';
    
    // Auto Abuse Email Generator Logic
    $isp_lower = strtolower($isp);
    $abuse_email = "abuse@{$host}"; // Default fallback
    if (strpos($isp_lower, 'cloudflare') !== false) $abuse_email = "abuse@cloudflare.com";
    elseif (strpos($isp_lower, 'namecheap') !== false) $abuse_email = "abuse@namecheap.com";
    elseif (strpos($isp_lower, 'godaddy') !== false) $abuse_email = "abuse@godaddy.com";
    elseif (strpos($isp_lower, 'hostinger') !== false) $abuse_email = "abuse@hostinger.com";
    elseif (strpos($isp_lower, 'amazon') !== false || strpos($isp_lower, 'aws') !== false) $abuse_email = "trustandsafety@support.aws.com";

    // Phishing Risk Heuristics
    stream_context_set_default(['http' => ['method' => 'HEAD', 'timeout' => 2]]);
    $headers = @get_headers("https://" . $host, 1);
    $ssl_issuer = 'Unknown';
    $context = stream_context_create(["ssl" => ["capture_peer_cert" => true, "verify_peer" => false]]);
    $client = @stream_socket_client("ssl://{$host}:443", $errno, $errstr, 2, STREAM_CLIENT_CONNECT, $context);
    if ($client) {
        $params = stream_context_get_params($client);
        if (isset($params["options"]["ssl"]["peer_certificate"])) {
            $cert = openssl_x509_parse($params["options"]["ssl"]["peer_certificate"]);
            $ssl_issuer = $cert['issuer']['O'] ?? 'Unknown';
        }
    }

    echo json_encode([
        'status' => 'success',
        'target' => $host,
        'ip' => $ip,
        'isp' => $isp,
        'country' => $geo['country'] ?? 'Unknown',
        'abuse_email' => $abuse_email,
        'ssl_issuer' => $ssl_issuer,
        'risk_level' => ($ssl_issuer === 'Let\'s Encrypt' || strpos($isp_lower, 'cloudflare') !== false) ? 'HIGH RISK (Phishing Suspected)' : 'MODERATE RISK'
    ]);
    exit;
}
?>