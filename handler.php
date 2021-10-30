<?php

/**
 * LaraWall Iptables Handler
 *
 * @author   Ray Icemont <ray.icemont@gmail.com>
 * @license  https://opensource.org/licenses/MIT
 * @package  larawall-iptables-handler
 */

use Icemont\cURL\CurlWrapper;
use Icemont\Larawall\IptablesHandler\Firewall;

define('MAIN_DIR', dirname(__FILE__));
$start_time = microtime(true);

$lock_fp = fopen(MAIN_DIR . '/.lock', 'w');

if (!flock($lock_fp, LOCK_EX | LOCK_NB)) {
    fclose($lock_fp);
    exit('- Error: handler already running!' . PHP_EOL .
        '- Exiting now' . PHP_EOL);
}

echo '- Running the Larawall iptables handler' . PHP_EOL;

require_once MAIN_DIR . '/vendor/autoload.php';
$config = require_once MAIN_DIR . '/config/config.php';

$api_data = json_decode((new CurlWrapper)->request($config['api_data_endpoint']));

if ($api_data) {
    $iptables = new Firewall();

    $iptables_rules = $iptables->getIptablesRules();
    $ipsets = $iptables->getIpsets();

    if ($api_data->status == 'ok') {
        foreach ($api_data->data->services as $service) {
            if (!$service->status) {
                continue;
            }

            if (array_key_exists($service->id, $ipsets)) {
                unset($ipsets[$service->id]);
            } else {
                echo '- Adding new ipset #' . $service->id . PHP_EOL;
                $iptables->addIpset($service->id);
            }

            if (array_key_exists($service->id, $iptables_rules)) {
                if ($service->updated > $iptables_rules[$service->id]['updated']) {
                    $rule_comment = implode(',', ['larawall', $service->id, $service->updated]);
                    echo '- Updating iptables rule for service #' . $service->id . PHP_EOL;
                    $iptables->updateIptablesRule($service->id, $service->port, $service->id, $rule_comment);
                }
                unset($iptables_rules[$service->id]);
            } else {
                $rule_comment = implode(',', ['larawall', $service->id, $service->updated]);
                echo '- Adding new iptables rule for service #' . $service->id . PHP_EOL;
                $iptables->addIptablesRule($service->port, $service->id, $rule_comment);
            }
        }
    }

    if (in_array($api_data->status, ['ok', 'disabled'])) {
        foreach ($iptables_rules as $service_id => $rule) {
            echo '- Deleting iptables rule for service #' . $service_id . PHP_EOL;
            $iptables->deleteIptablesRule($service_id);
        }

        foreach ($ipsets as $service_id => $set) {
            echo '- Deleting ipset #' . $service_id . PHP_EOL;
            $iptables->deleteIpset($service_id);
        }
    }

    $iptables_rules = $iptables->getIptablesRules(true);
    $ipsets = $iptables->getIpsets(true);

    foreach ($api_data->data->customer_ips as $customer_ip) {
        if (!$customer_ip->status || !isset($ipsets[$customer_ip->service_id])) {
            continue;
        }

        if ($ip = array_search($customer_ip->id, $ipsets[$customer_ip->service_id])) {
            unset($ipsets[$customer_ip->service_id][$ip]);
        } else {
            echo '- Adding new rule "' . $customer_ip->ip . '" to ipset #' . $customer_ip->service_id . PHP_EOL;

            $comment = implode(',', [
                $customer_ip->id,
                $customer_ip->service_id,
                $customer_ip->package_id,
                $customer_ip->subscription_id,
                $customer_ip->customer_id,
                $customer_ip->updated,
            ]);
            $iptables->addIpsetRule($customer_ip->service_id, $customer_ip->ip, $comment);
        }
    }

    foreach ($ipsets as $service_id => $ipset_rules) {
        if (!count($ipset_rules)) {
            continue;
        }

        echo '- Deleting unwanted rules from ipset #' . $service_id . ':' . PHP_EOL;
        foreach ($ipset_rules as $ip => $ip_id) {
            echo '-- Deleting rule "' . $ip . '"' . PHP_EOL;
            $iptables->deleteIpsetRule($service_id, $ip);
        }
    }

} else {
    echo '- Error: failed to retrieve API data' . PHP_EOL;
}

flock($lock_fp, LOCK_UN);
fclose($lock_fp);

echo 'Execution time: ' . round(microtime(1) - $start_time, 1) . ' sec.' . PHP_EOL;
