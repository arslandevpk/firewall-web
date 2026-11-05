from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parent.parent


class PackagingConfigurationTests(unittest.TestCase):
    def test_backend_conflict_acknowledgement_reaches_openrc_service(self):
        config = (ROOT / 'packaging/firewall-web.conf').read_text()
        service = (ROOT / 'packaging/firewall-web.openrc').read_text()
        wrapper = (ROOT / 'packaging/firewall-web').read_text()
        debian_config = (ROOT / 'firewall-web-standalone/firewall-web.env.example').read_text()
        self.assertIn('NFT_BACKEND_ACK=', config)
        self.assertIn('NFT_BACKEND_ACK=', debian_config)
        self.assertIn('command="/usr/bin/firewall-web"', service)
        self.assertIn('--config /etc/conf.d/firewall-web', service)
        self.assertIn('exec "$python" "$helper" exec --config "$config"', wrapper)
        self.assertNotRegex(wrapper, r'\b(?:source|eval)\b')

    def test_debian_package_does_not_enable_service_during_install(self):
        rules = (ROOT / 'debian/rules').read_text()
        builder = (ROOT / 'packaging/build-deb.sh').read_text()
        self.assertIn('dh_installsystemd --no-enable --no-start', rules)
        self.assertNotIn('systemctl enable', builder)


if __name__ == '__main__':
    unittest.main()
