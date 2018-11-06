<?php

namespace AbuseIO\Parsers;

use AbuseIO\Models\Incident;
use Tele2\Odin\Db\OSA;
use Validator;

/**
 * Class HaveIBeenPwnd
 * @package AbuseIO\Parsers
 */
class HaveIBeenPwnd extends Parser
{
    /**
     * @var string[]
     *
     * The AbuseIO domain validator does not accept subdomains.
     * We will filter them out, but we need to take special care when
     * dealing with composite TLDs.
     * A better solution would be if the domain validator accepted subdomains.
     */
    protected static $composite_tlds = [
        'co.uk',
        'ac.uk',
        'co.nz',
        'co.za',
        'com.au',
        'com.us',
        'gov.us',
        'edu.us',
    ];

    /**
     * Create a new HaveIBeenPwnd instance
     *
     * @param \PhpMimeMailParser\Parser $parsedMail phpMimeParser object
     * @param array $arfMail array with ARF detected results
     */
    public function __construct($parsedMail, $arfMail)
    {
        parent::__construct($parsedMail, $arfMail, $this);
    }

    /**
     * Parse attachments
     * @return array    Returns array with failed or success data
     *                  (See parser-common/src/Parser.php) for more info.
     */
    public function parse()
    {
        $reports = $this->_getRecords($this->parsedMail);
        \Log::debug(print_r($reports, true));

        if (!empty($reports) && is_array($reports)) {
            foreach ($reports as $report) {
                $this->feedName = $report['feed'];

                // If feed is known and enabled, validate data and save report
                if ($this->isKnownFeed() && $this->isEnabledFeed()) {
                    // Sanity check
                    if ($this->hasRequiredFields($report) === true) {
                        // incident has all requirements met, add it!

                        $incident = new Incident();
                        $incident->source      = config("{$this->configBase}.parser.name");
                        $incident->source_id   = false;
                        $incident->ip          = $report['ip'];
                        $incident->domain      = $report['domain'];
                        $incident->class       = config("{$this->configBase}.feeds.{$this->feedName}.class");
                        $incident->type        = config("{$this->configBase}.feeds.{$this->feedName}.type");
                        $incident->timestamp   = $report['timestamp'];
                        $incident->information = json_encode($report);

                        $validator = Validator::make($incident->toArray(), Incident::createRules());

                        if ($validator->passes()) {
                            $this->incidents[] = $incident;
                        } else {
                            \Log::debug($incident->toArray());
                        }
                    }
                }
            }
        }

        return $this->success();
    }

    /**
     * return reports found in the parsedMail
     *
     * @param $parsedMail
     * @return array
     */
    private function _getRecords($parsedMail)
    {
        $reports = [];

        $body = $parsedMail->getMessageBody();
        $timestamp = strtotime($parsedMail->getHeader('date'));
        $subject = $parsedMail->getHeader('subject');
        $domain = $this->_getDomain($subject);

        if ($domain) {
            $mx = $this->_getPreferredMXRecord($domain);
            \Log::debug(print_r($this->_getPreferredMXRecord($domain), true));

            if (!empty($mx)) {
                $report['feed'] = 'Default';
                $report['domain'] = $domain;
                $report['ip'] = $mx['ip'];
                $report['timestamp'] = $timestamp;
                $report['data'] = [];
                $report['data']['body'] = $body;
                $report['data']['mx'] = $mx;
                $report['data']['breach'] = [];

                $reports[] = $report;
            }
        }

        \Log:;debug(print_r($reports, true));
        // TODO there is breach info in the base64 encode htmlmail, add that info to the report breach data

        return $reports;
    }

    /**
     * return the domain of the incident if available
     *
     * @param $subject
     * @return mixed
     */
    private function _getDomain($subject)
    {
        $domain = null;

        if (preg_match('/^An email on (\S+?\.\S+?) has been/', $subject, $matches) == 1) {
            $domain = $matches[1];

            // if we have a subdomain only get the domain and tld part
            if (preg_match('/^([^.]+?\.)*               # any other parts
                                ([^.]+?\.)+             # last-but-two part
                                ([^.]+?\.[^.]+?)$/x',   # last two parts
                    $domain, $matches) == 1)
            {
                $domain = $matches[3];
                // If we have a '<subdomain>.<company>.co.uk' situation, keep only
                // the '<company>.co.uk' part
                if (in_array($domain, self::$composite_tlds)) {
                    $domain = $matches[2] . $matches[3];
                }
            }
        }

        return $domain;
    }

    /**
     * return the mx record of a domain with the lowest weight or an empty array on error
     *
     * @param $domain
     * @return array
     */
    private function _getPreferredMXRecord($domain)
    {
        $mx = [];
        $weight = [];
        $result = [];

        if (getmxrr($domain, $mx, $weight))
        {
            // find the lowest weight and the matching index
            $current_weight = null;
            $current_index = null;
            foreach ($weight as $index => $w) {
                if (is_null($current_weight)) {
                    $current_weight = $w;
                    $current_index = $index;
                } else {
                    if ($w < $current_weight) {
                        $current_weight = $w;
                        $current_index = $index;
                    }
                }
            }

            // get the preferred mx and its ip
            if (!is_null($current_index))
            {
                $result['mx'] = $mx[$current_index];
                $result['weight'] = $current_weight;
                $result['ip'] = gethostbyname($mx[$current_index]);
            }
        }

        return $result;
    }
}

