<?php

/**
 * Class for managing Iptables rules for the LaraWall Iptables Handler
 *
 * @author   Ray Icemont <ray.icemont@gmail.com>
 * @license  https://opensource.org/licenses/MIT
 * @package  larawall-iptables-handler
 */

namespace Icemont\Larawall\IptablesHandler;

use InvalidArgumentException;

class Firewall
{
    /**
     * Iptables rules list
     *
     * @var array
     */
    private $iptables_rules = [];

    /**
     * Ipsets list
     *
     * @var array
     */
    private $ipsets = [];

    /**
     * Creates new Iptables rule management instance for LaraWall
     */
    public function __construct()
    {
        $this->loadIptablesRules();
        $this->loadIpsets();
    }

    /**
     * Returns the current list of Iptables rules
     *
     * @param bool $reload
     * @return array
     */
    public function getIptablesRules(bool $reload = false): array
    {
        return $reload ? $this->loadIptablesRules() : $this->iptables_rules;
    }

    /**
     * Returns the current list of Ipsets
     *
     * @param bool $reload
     * @return array
     */
    public function getIpsets(bool $reload = false): array
    {
        return $reload ? $this->loadIpsets() : $this->ipsets;
    }

    /**
     * Adds a new Iptables rule
     *
     * @param int $port
     * @param int $ipset_id
     * @param string|null $comment
     * @return false|string
     */
    public function addIptablesRule(int $port, int $ipset_id, ?string $comment = null)
    {
        if ($comment && strpos($comment, '"') !== false) {
            throw new InvalidArgumentException('Comment must not contain quotes!');
        }

        $command = '/usr/sbin/iptables -A INPUT -p tcp -m tcp -m set --match-set larawall_' .
            $ipset_id . ' src --dport ' . $port .
            ($comment ? ' -m comment --comment "' . $comment . '"' : '') . ' -j ACCEPT';
        return exec($command);
    }

    /**
     * Adds a new Ipset
     *
     * @param int $ipset_id
     * @return false|string
     */
    public function addIpset(int $ipset_id)
    {
        $command = '/usr/sbin/ipset -q -N larawall_' . $ipset_id . ' iphash comment';
        return exec($command);
    }

    /**
     * Updates existing Iptables rule
     *
     * @param int $service_id
     * @param int $port
     * @param int $ipset_id
     * @param string|null $comment
     * @return false|string
     */
    public function updateIptablesRule(int $service_id, int $port, int $ipset_id, ?string $comment = null)
    {
        if (!array_key_exists($service_id, $this->iptables_rules)) {
            throw new InvalidArgumentException('No rule with this identifier was found!');
        }
        if ($comment && strpos($comment, '"') !== false) {
            throw new InvalidArgumentException('Comment must not contain quotes!');
        }

        $command = '/usr/sbin/iptables -R INPUT ' . $this->iptables_rules[$service_id]['line'] . ' -p tcp -m tcp -m set --match-set larawall_' .
            $ipset_id . ' src --dport ' . $port .
            ($comment ? ' -m comment --comment "' . $comment . '"' : '') . ' -j ACCEPT';
        return exec($command);
    }

    /**
     * Deletes existing Iptables rule
     *
     * @param int $service_id
     * @return array
     */
    public function deleteIptablesRule(int $service_id): array
    {
        if (!array_key_exists($service_id, $this->iptables_rules)) {
            throw new InvalidArgumentException('No rule with this identifier was found!');
        }

        $command = '/usr/sbin/iptables -D INPUT ' . $this->iptables_rules[$service_id]['line'];
        exec($command);

        return $this->loadIptablesRules();
    }

    /**
     * Deletes existing Ipset
     *
     * @param int $set_id
     * @return array
     */
    public function deleteIpset(int $set_id): array
    {
        $command = '/usr/sbin/ipset destroy larawall_' . $set_id;
        exec($command);

        return $this->loadIpsets();
    }

    /**
     * Adds rule to existing Ipset
     *
     * @param int $ipset_id
     * @param string $ip
     * @param string $comment
     * @return false|string
     */
    public function addIpsetRule(int $ipset_id, string $ip, string $comment)
    {
        if (!$ip = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            throw new InvalidArgumentException('Variable "ip" must be a valid IPv4 address!');
        }
        if ($comment && strpos($comment, '"') !== false) {
            throw new InvalidArgumentException('Comment must not contain quotes!');
        }

        $command = '/usr/sbin/ipset add larawall_' . $ipset_id . ' ' . $ip .
            ($comment ? ' comment "' . $comment . '"' : '');
        return exec($command);
    }

    /**
     * Deletes a rule from existing Ipset
     *
     * @param int $ipset_id
     * @param string $ip
     * @return false|string
     */
    public function deleteIpsetRule(int $ipset_id, string $ip)
    {
        if (!$ip = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            throw new InvalidArgumentException('Variable "ip" must be a valid IPv4 address!');
        }

        $command = '/usr/sbin/ipset del larawall_' . $ipset_id . ' ' . $ip;
        return exec($command);
    }

    /**
     * @return array
     */
    private function loadIptablesRules(): array
    {
        $this->iptables_rules = [];

        exec('/usr/sbin/iptables -L INPUT -n -v --line-numbers | grep -E \'larawall\'', $fw_data);
        $fw_data = implode("\n", $fw_data);

        if (preg_match_all('|^([0-9]+)\s+.*\s+dpt:([0-9]+)\s+.*\s+larawall,([0-9]+),([0-9]+)\s+|Uism', $fw_data, $fw_m)) {
            foreach ($fw_m[3] as $fw_key => $fw_val) {
                $this->iptables_rules[$fw_val] = [
                    'line' => $fw_m[1][$fw_key],
                    'port' => $fw_m[2][$fw_key],
                    'updated' => $fw_m[4][$fw_key]
                ];
            }
        }

        return $this->iptables_rules;
    }

    /**
     * @return array
     */
    private function loadIpsets(): array
    {
        $this->ipsets = [];

        exec('/usr/sbin/ipset list -o xml', $fw_data);
        $fw_data = implode("\n", $fw_data);

        $xml = simplexml_load_string($fw_data, 'SimpleXMLElement', LIBXML_NOCDATA);

        foreach ($xml->ipset as $set) {
            $set_name = (string)$set->attributes()->name;
            if (stripos($set_name, 'larawall_') !== 0) {
                continue;
            }
            $set_name = substr($set_name, 9);
            $this->ipsets[$set_name] = [];
            foreach ($set->members->member as $member) {
                $comment = str_replace('"', '', (string)$member->comment);
                $member_id = intval(strtok($comment, ','));
                $this->ipsets[$set_name][(string)$member->elem] = $member_id;
            }
        }

        return $this->ipsets;
    }
}
