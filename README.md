# Zhortein Dev Security Bundle

> 🔒 Secure your Symfony dev environment without losing comfort.

[![CI](https://github.com/zhortein/dev-security-bundle/actions/workflows/ci.yml/badge.svg)](https://github.com/zhortein/dev-security-bundle/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/zhortein/dev-security-bundle/branch/develop/graph/badge.svg)](https://codecov.io/gh/zhortein/dev-security-bundle)
[![PHP Version](https://img.shields.io/badge/PHP->=8.3-blue.svg)](https://php.net)
[![Symfony Version](https://img.shields.io/badge/Symfony-7.0+-orange.svg)](https://symfony.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

This bundle protects Symfony development environments from accidental exposure of sensitive data.  
It restricts access to the **Web Debug Toolbar**, **Profiler**, and other **debug routes** to a whitelist of IPs or reverse hostnames.

---

## 🚀 Installation

```bash
composer require --dev zhortein/dev-security-bundle
```

Then register it (Symfony Flex usually handles this automatically):

```php
// config/bundles.php
return [
    Zhortein\DevSecurityBundle\ZhorteinDevSecurityBundle::class => ['dev' => true, 'test' => true],
];
```

---

## ⚙️ Configuration

Create <code>config/packages/zhortein_dev_security.yaml</code> with configuration options:

```yaml
zhortein_dev_security:
    enabled: true
    allowed_ips:
        - 127.0.0.1
        - ::1
        - 192.168.1.0/24
        - 10.8.0.0/16
    allowed_hosts:
        - "*.mydomain.fr"
        - "*.otherdomain.com"
    log_blocked_attempts: true
```

---

## 🧠 Features

✅ Restricts Symfony Web Debug Toolbar & Profiler to allowed IPs / CIDR / hostnames
✅ Logs blocked attempts for audit
✅ Optional <code>#[RestrictedToDevWhitelist]</code> attribute to secure sensitive routes (e.g. <code>/dev/info</code>)
✅ Zero dependency, works out of the box

--- 

## 🧰 Usage Example

```php
use Zhortein\DevSecurityBundle\Attribute\RestrictedToDevWhitelist;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

#[Route('/dev/info')]
#[RestrictedToDevWhitelist]
public function devInfo(): Response
{
    return new Response('This route is visible only to authorized developer IPs.');
}
```

If accessed from an unauthorized IP, the bundle throws <code>AccessDeniedHttpException</code> (403).

--- 

## 🛠️ Roadmap

| Version | Feature                                                     |
| ------- | ----------------------------------------------------------- |
| 1.0.0   | Base security (profiler restriction, route attribute)       |
| 1.1.0   | Command-line helper to list current IPs and detect reverses |
| 1.2.0   | Middleware to disable exception stacktraces in preprod      |
| 2.0.0   | Audit dashboard & metrics integration                       |

---

## 🧑‍💻 Author

[David Renard](https://www.david-renard.fr/?utm_source=github&utm_medium=banner&utm_campaign=david-renard-fr&utm_content=zhortein-dev-security-bundle)
CEO at [Isatis Concept](https://www.isatis-concept.fr?utm_source=github&utm_medium=banner&utm_campaign=isatis-concept&utm_content=zhortein-dev-security-bundle)

## 📝 License
MIT © David Renard
