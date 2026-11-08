import importlib.util,os,unittest
from pathlib import Path
from unittest.mock import patch
class HealthTests(unittest.TestCase):
 def test_health_is_authenticated_and_does_not_inventory_firewall(self):
  with patch.dict(os.environ,{'NFT_SECRET':'7391'}):
   spec=importlib.util.spec_from_file_location('health_fw',Path(__file__).with_name('firewall_web.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
  with patch.object(m,'detect_firewall',side_effect=AssertionError('health must not inventory')),patch.object(m,'current_detection',side_effect=AssertionError('health must not inventory')):
   c=m.app.test_client()
   self.assertEqual(c.get('/api/health').status_code,401)
   r=c.get('/api/health',headers={'X-Secret':'7391'})
   self.assertEqual(r.status_code,200);self.assertEqual(r.get_json(),{'ok':True})
if __name__=='__main__':unittest.main()
