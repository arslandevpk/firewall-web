const { test, expect } = require('@playwright/test');

const sections = [
  'overview',
  'manager',
  'nft',
  'ipt',
  'masq',
  'persistence',
  'backups',
  'advanced',
  'display',
];

function detection(backend) {
  const active = backend === 'ufw' ? 'active' : 'inactive';
  return {
    managers: {
      ufw: { status: backend === 'ufw' ? 'active' : 'inactive', version: 'fixture' },
      firewalld: {
        status: backend === 'firewalld' ? 'active' : 'inactive',
        version: 'fixture',
        capabilities: {},
      },
    },
    direct: {
      nftables: { status: 'empty', underlying_packet_filter: 'nf_tables' },
      iptables: { status: 'empty', default_implementation: 'iptables-nft' },
    },
    persistence: {
      netfilter_persistent: { active: false },
      native_restore: { active: false },
    },
    forwarding: { ipv4: false, ipv6: false },
    service_owners: [],
    active_managers: backend === 'ufw' || backend === 'firewalld' ? [backend] : [],
    conflict_acknowledgement: null,
    selected_backend: backend,
    write_backends: [],
    reason: `${backend} fixture`,
    can_write: false,
    manager_can_write: false,
    selection_review_required: false,
    fingerprint_review_required: false,
    previous_backend: null,
    listeners: 'fixture',
    _active: active,
  };
}

async function installApiFixtures(page, initialBackend = 'inspection') {
  let backend = initialBackend;
  const calls = [];
  await page.route('**/api/**', async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    calls.push({ path, method: request.method() });
    const selected = detection(backend);
    let body;
    if (path === '/api/status') {
      body = {
        nft: true,
        backends: ['iptables', 'iptables-nft'],
        detection: selected,
        root: false,
        interfaces: ['lo', 'eth0'],
        can_manage_firewall: false,
        read_only_reason: 'Fixture is intentionally read-only.',
        forwarding: { ip: false, ip6: false },
      };
    } else if (path === '/api/detection') {
      body = selected;
    } else if (path === '/api/ufw') {
      body = {
        state_token: 'ufw-token',
        status: 'Status: active',
        ipv6: 'yes',
        rules: [{ number: 1, text: '22/tcp ALLOW IN', token: 'rule-token' }],
      };
    } else if (path === '/api/firewalld') {
      body = {
        state_token: 'firewalld-token',
        version: 'fixture',
        default_zone: 'public',
        permanent_default_zone: 'public',
        active_zones: { public: ['eth0'] },
        zones: { public: { services: ['ssh'], ports: [], sources: [], interfaces: [] } },
        policies: {},
        capabilities: {
          source_bindings: true,
          zone_bindings: true,
          rich_rules: true,
          policies: false,
        },
      };
    } else if (path === '/api/overview') {
      const state = {
        chains: [],
        rules: [],
        raw: '',
        version: 'fixture',
        backend: 'iptables',
      };
      body = { states: { nft: { ...state }, iptables: { ...state }, 'iptables-nft': { ...state } } };
    } else {
      return route.fulfill({ status: 404, json: { error: `Unexpected fixture request: ${path}` } });
    }
    return route.fulfill({ status: 200, json: body });
  });
  return {
    calls,
    setBackend(value) {
      backend = value;
    },
  };
}

async function unlock(page, hash = '') {
  await page.goto(`/${hash}`);
  await page.locator('#key').fill('1234');
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.locator('#app')).toBeVisible();
}

async function expectOneSelectedPanel(page, selected) {
  const visible = await page.locator('[role="tabpanel"]').evaluateAll((panels) =>
    panels.filter((panel) => getComputedStyle(panel).display !== 'none').map((panel) => panel.id),
  );
  expect(visible).toHaveLength(1);
  expect(visible[0]).toBe(selected);
  await expect(page.locator(`#tab-${selected}`)).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator(`#tab-${selected}`)).toHaveClass(/active/);
}

async function selectTab(page, id, isMobile) {
  const menu = page.locator('#menu-toggle');
  if (isMobile && (await menu.getAttribute('aria-expanded')) !== 'true') {
    await menu.click();
  }
  await page.locator(`#tab-${id}`).click();
}

test('all sections, ARIA relationships, and manager content stay in their own panel', async ({ page, isMobile }) => {
  const errors = [];
  const api = await installApiFixtures(page, 'inspection');
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => message.type() === 'error' && errors.push(message.text()));
  await unlock(page);

  const structure = await page.evaluate(() => {
    const ids = [...document.querySelectorAll('[id]')].map((node) => node.id);
    const panels = [...document.querySelectorAll('[role="tabpanel"]')];
    const tabs = [...document.querySelectorAll('[role="tab"]')];
    return {
      duplicateIds: ids.filter((id, index) => ids.indexOf(id) !== index),
      relationshipsValid: tabs.every((tab) => {
        const panel = document.getElementById(tab.getAttribute('aria-controls'));
        return panel && panel.getAttribute('aria-labelledby') === tab.id;
      }) && panels.every((panel) => document.getElementById(panel.getAttribute('aria-labelledby'))),
      count: tabs.length,
    };
  });
  expect(structure.duplicateIds).toEqual([]);
  expect(structure.relationshipsValid).toBe(true);
  expect(structure.count).toBe(sections.length);

  for (const id of sections) {
    await selectTab(page, id, isMobile);
    await expectOneSelectedPanel(page, id);
    const managerBlockVisible =
      (await page.locator('#detection-heading').isVisible()) ||
      (await page.locator('#ufw-controls').isVisible()) ||
      (await page.locator('#firewalld-controls').isVisible());
    expect(managerBlockVisible).toBe(id === 'manager');
  }
  expect(api.calls.some((call) => call.method !== 'GET')).toBe(false);
  expect(errors).toEqual([]);
});

test('UFW, firewalld, direct, and inspection detection changes preserve selected navigation', async ({ page, isMobile }) => {
  const errors = [];
  const api = await installApiFixtures(page, 'ufw');
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => message.type() === 'error' && errors.push(message.text()));
  await unlock(page);
  await selectTab(page, 'manager', isMobile);
  await expect(page.locator('#ufw-controls')).toBeVisible();
  await expect(page.locator('#ufw-rules')).toContainText('22/tcp ALLOW IN');
  await expectOneSelectedPanel(page, 'manager');

  for (const [backend, visibleControl] of [
    ['firewalld', '#firewalld-controls'],
    ['iptables', null],
    ['nftables', null],
    ['inspection', null],
    ['ufw', '#ufw-controls'],
  ]) {
    api.setBackend(backend);
    await page.locator('#refresh-detection').click();
    if (visibleControl) {
      await expect(page.locator(visibleControl)).toBeVisible();
    }
    await expect(page.locator(backend === 'ufw' ? '#firewalld-controls' : '#ufw-controls')).toBeHidden();
    if (backend !== 'firewalld') {
      await expect(page.locator('#firewalld-controls')).toBeHidden();
    }
    await expectOneSelectedPanel(page, 'manager');
  }

  await selectTab(page, 'overview', isMobile);
  api.setBackend('firewalld');
  await page.locator('#refresh').click();
  await expect(page.locator('#firewalld-controls')).toBeHidden();
  await expectOneSelectedPanel(page, 'overview');
  expect(api.calls.some((call) => call.method !== 'GET')).toBe(false);
  expect(errors).toEqual([]);
});

test('hash navigation, reload, keyboard operation, mobile drawer, and locking remain synchronized', async ({ page, isMobile }) => {
  const errors = [];
  await installApiFixtures(page, 'inspection');
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => message.type() === 'error' && errors.push(message.text()));
  await unlock(page, '#manager');
  await expectOneSelectedPanel(page, 'manager');
  await expect(page).toHaveURL(/#manager$/);
  await page.reload();
  await expect(page.locator('#login')).toBeVisible();
  await unlock(page, '#manager');
  await expectOneSelectedPanel(page, 'manager');

  if (isMobile) {
    const menu = page.locator('#menu-toggle');
    await menu.click();
    await expect(menu).toHaveAttribute('aria-expanded', 'true');
    await expect(page.locator('#workspace')).toHaveJSProperty('inert', true);
    await page.keyboard.press('Escape');
    await expect(menu).toHaveAttribute('aria-expanded', 'false');
    await expect(menu).toBeFocused();
    await menu.click();
  }

  await page.locator('#tab-overview').focus();
  await page.keyboard.press('ArrowDown');
  await expect(page.locator('#tab-manager')).toBeFocused();
  await expectOneSelectedPanel(page, 'manager');
  await page.keyboard.press('End');
  await expect(page.locator('#tab-display')).toBeFocused();
  await expectOneSelectedPanel(page, 'display');

  if (isMobile) {
    await page.locator('#tab-manager').click();
    await expect(page.locator('#menu-toggle')).toHaveAttribute('aria-expanded', 'false');
    await expectOneSelectedPanel(page, 'manager');
  }
  const selectedBeforeLock = isMobile ? 'manager' : 'display';

  await page.getByRole('button', { name: 'Lock' }).click();
  await expect(page.locator('#app')).toBeHidden();
  await expect(page.locator('#login')).toBeVisible();
  await expect(page.locator('#key')).toHaveValue('');
  await expect(page.locator('#connection')).toHaveText('Locked');
  await page.locator('#key').fill('1234');
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.locator('#app')).toBeVisible();
  await expectOneSelectedPanel(page, selectedBeforeLock);
  expect(errors).toEqual([]);
});

test('background detection refresh cannot reveal an inactive manager panel', async ({ page, isMobile }) => {
  const errors = [];
  const api = await installApiFixtures(page, 'ufw');
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => message.type() === 'error' && errors.push(message.text()));
  await page.clock.install();
  await unlock(page);
  await selectTab(page, 'overview', isMobile);
  api.setBackend('firewalld');
  const previousDetections = api.calls.filter((call) => call.path === '/api/detection').length;
  await page.clock.fastForward(15000);
  await expect.poll(() => api.calls.filter((call) => call.path === '/api/detection').length)
    .toBeGreaterThan(previousDetections);
  await expect(page.locator('#firewalld-controls')).toBeHidden();
  await expect(page.locator('#ufw-controls')).toBeHidden();
  await expectOneSelectedPanel(page, 'overview');
  expect(errors).toEqual([]);
});
