import unittest
from html.parser import HTMLParser

import firewall_web as fw


MANAGER_CONTENT_IDS = {
    'detection-heading', 'detection-summary', 'detection-details',
    'refresh-detection', 'review-detection', 'ufw-controls', 'ufw-add',
    'ufw-default', 'ufw-status', 'ufw-rules', 'firewalld-controls',
    'firewalld-add', 'firewalld-status', 'firewalld-reload',
}


class NavigationMarkup(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.tabs = []
        self.panels = []
        self.manager_content_panels = {}
        self.stack = []

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        element_id = attrs.get('id')
        if element_id:
            if element_id in self.ids:
                raise AssertionError(f'Duplicate id: {element_id}')
            self.ids.add(element_id)
        if attrs.get('role') == 'tab':
            self.tabs.append((element_id, attrs.get('aria-controls'), attrs.get('aria-selected'),
                              attrs.get('tabindex')))
        if attrs.get('role') == 'tabpanel':
            self.panels.append((element_id, attrs.get('aria-labelledby'),
                                'hidden' in attrs.get('class', '').split(),
                                attrs.get('tabindex')))
        current_panel = next((panel for _, panel in reversed(self.stack) if panel), None)
        if element_id in MANAGER_CONTENT_IDS:
            self.manager_content_panels[element_id] = current_panel
        panel = element_id if attrs.get('role') == 'tabpanel' else None
        if tag not in ('area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input',
                       'link', 'meta', 'param', 'source', 'track', 'wbr'):
            self.stack.append((tag, panel))

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return


class NavigationMarkupTests(unittest.TestCase):
    def setUp(self):
        self.document = NavigationMarkup()
        self.document.feed(fw.HTML)

    def test_tab_controls_and_panels_have_unique_matching_accessible_relationships(self):
        panels = {panel_id: (labelledby, hidden, tabindex)
                  for panel_id, labelledby, hidden, tabindex in self.document.panels}
        self.assertEqual(len(self.document.tabs), len(panels))
        self.assertEqual(sum(not hidden for _, _, hidden, _ in self.document.panels), 1)
        for tab_id, controls, selected, _ in self.document.tabs:
            self.assertIn(controls, panels)
            labelledby, hidden, tabindex = panels[controls]
            self.assertEqual(labelledby, tab_id)
            self.assertEqual(selected, str(not hidden).lower())
            self.assertEqual(tabindex, '0')
            self.assertEqual(_, '0' if selected == 'true' else '-1')

    def test_all_manager_status_forms_and_rules_are_inside_manager_panel(self):
        self.assertIn(('tab-manager', 'manager', 'false', '-1'), self.document.tabs)
        self.assertIn('manager', {panel_id for panel_id, _, _, _ in self.document.panels})
        self.assertEqual(self.document.manager_content_panels,
                         {element_id: 'manager' for element_id in MANAGER_CONTENT_IDS})
        self.assertIn("manager:['Firewall Manager'", fw.HTML)
        self.assertIn("window.addEventListener('hashchange'", fw.HTML)
        self.assertIn("if(e.key==='ArrowDown')", fw.HTML)
        self.assertIn("setSidebar(!$('app').classList.contains('sidebar-open'))", fw.HTML)

    def test_detection_refresh_does_not_change_panel_visibility(self):
        detection = fw.HTML.split('function renderDetection(d){', 1)[1].split(
            '\nfunction configureBackends()', 1)[0]
        self.assertNotIn('activateTab(', detection)
        self.assertNotIn("querySelectorAll('.panel')", detection)
        self.assertIn("for(const p of document.querySelectorAll('.panel'))p.classList.toggle('hidden',p.id!==id)",
                      fw.HTML)


if __name__ == '__main__':
    unittest.main()
