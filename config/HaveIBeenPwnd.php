<?php

return [
    'parser' => [
        'name'          => 'HaveIBeenPwnd',
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
            'class'     => 'HAVE_I_BEEN_PWND_DOMAIN_FOUND',
            'type'      => 'ABUSE',
            'enabled'   => true,
            'fields'    => [
                'ip',
                'domain',
            ],
            'fallback_ip' => '127.0.0.1',
        ],
    ],
];
