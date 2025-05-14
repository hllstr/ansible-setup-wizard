# ansible-auto-setup
```markdown
> A Bash-powered interactive Ansible project generator for automating basic service deployments on Linux and Windows systems.

This tool helps you quickly scaffold a production-style Ansible project by answering a few prompts. It generates roles, inventories, configuration, and integrates Jinja2 templates — all tailored to the services and hosts you define.
```
---

## 🧩 Features

- ✅ Fully interactive CLI-based setup
- 🔐 Secure & insecure protocol support (SSH / WinRM)
- 🧠 Smart OS detection based on hostname (e.g., `LIN1`, `WIN1`)
- ⚙️ Auto-generates:
  - `ansible.cfg`
  - Inventory file (`hosts.ini`)
  - Roles per OS/service
  - Playbook (`main.yml`)
- 📄 Template system with Jinja2 support
- 💬 Comments and TODOs for easy customization

---

## 📦 Project Structure

```
ansible-project/
├── ansible.cfg
├── inventory/
│   └── hosts.ini
├── group_vars/
├── host_vars/
├── playbooks/
│   └── main.yml
├── roles/
│   └── linux_apache2/
│   └── windows_dns/
│      ...
├── templates/
│   └── apache2.j2
│   └── iis.j2
└── README.md
```

---

## 🚀 Quick Start

```bash
chmod +x generate-ansible-project.sh
./generate-ansible-project.sh
```

Then just follow the interactive wizard to:

- Choose secure or insecure protocol mode
- Enter your hostnames (e.g., `LIN1`, `WIN1`)
- Define OS and services per host

---

## 💻 Supported Services

| Linux       | Windows        |
|-------------|----------------|
| apache2     | IIS (`webserver`) |
| bind9       | DNS            |
| haproxy     |                |

---

## 🔐 WinRM Security Modes

This script supports both secure (HTTPS) and insecure (HTTP) WinRM setup for Windows hosts.

### If using insecure:
```powershell
winrm quickconfig -q
winrm set winrm/config/service '@{AllowUnencrypted="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'
```

Use only in **lab/test environments**.

---

## 🧰 After Generation

1. **Review your inventory:**
   - Edit `inventory/hosts.ini` with actual IPs or FQDNs
   - Check WinRM or SSH credentials if needed

2. **Customize roles:**
   - Implement missing tasks in `roles/*/tasks/main.yml`
   - Adjust template paths as needed

3. **Edit variables:**
   - Define host/group-specific values in `host_vars/` or `group_vars/`

4. **Run the playbook:**
```bash
ansible-playbook playbooks/main.yml
```

---

## 📂 Template Integration

Ensure your Jinja2 templates (e.g., `apache2.j2`, `dns_win.j2`) exist in:
```
jinja2-templates/
```

They will be copied into the generated project under:
```
ansible-project/templates/
```

Each role will reference these as needed.

---

## 🛡️ Security Note

This tool sets `host_key_checking = False` and may allow insecure WinRM (HTTP) if selected.

**DO NOT use this in production environments without reviewing security implications.**

---

## 🤝 Contributing

Want to improve the generator or add more built-in templates/services?

Feel free to fork and enhance!

---

## 📘 References

- [Ansible Documentation](https://docs.ansible.com/)
- [WinRM Setup Guide](https://docs.ansible.com/ansible/latest/user_guide/windows_setup.html)
- [Jinja2 Templating](https://jinja.palletsprojects.com/)

---

Made with ❤️ to help you automate more with less YAML writing.

---

