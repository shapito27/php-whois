# php-whois

PHP class to retrieve WHOIS information.
## Installation
``composer require "phois/whois"``

## Example of usage

```php
<?php
require_once __DIR__ . '/src/Phois/Whois/Whois.php';

$domain = 'nabi.ir';

try {
    $domain = new Phois\Whois\Whois($domain);
} catch (InvalidArgumentException $e) {
    die($e->getMessage() . '\n');
}

if ($domain->isAvailable()) {
	echo "Domain is available\n";
} else {
	echo "Domain is registered\n";
}
```