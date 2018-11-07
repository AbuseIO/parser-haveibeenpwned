<?php

return [
    'parser' => [
        'name'          => 'HaveIBeenPwned',
        'enabled'       => true,
        'sender_map'    => [
            '/noreply@haveibeenpwned.com/',
        ],
        'body_map'      => [
            //
        ],
    ],

    'feeds' => [
        'Default' => [
            'class'     => 'HAVE_I_BEEN_PWNED_DOMAIN_FOUND',
            'type'      => 'INFO',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'domain',
            ],
            'fallback_ip' => '127.0.0.1',
        ],
    ],
];
