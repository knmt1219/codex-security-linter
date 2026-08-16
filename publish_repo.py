import requests
import subprocess
import sys

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if sys.stderr and hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

def main():
    p = subprocess.Popen(['git', 'credential', 'fill'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = p.communicate('protocol=https\nhost=github.com\n\n')
    creds = dict(line.split('=', 1) for line in out.strip().split('\n') if '=' in line)
    token = creds.get('password')
    user = creds.get('username', 'knmt1219')

    if not token:
        print("❌ Could not obtain GitHub token from credential manager.", file=sys.stderr)
        sys.exit(1)

    repo_name = 'codex-security-linter'
    description = 'AI-powered security linter for GitHub Pull Requests detecting secrets, vulnerabilities, and suggesting remediation patches.'

    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'codex-security-linter-setup'
    }

    print(f"🔍 Checking if repository {user}/{repo_name} exists on GitHub...")
    r = requests.get(f'https://api.github.com/repos/{user}/{repo_name}', headers=headers)

    if r.status_code == 200:
        print(f"ℹ️ Repository {user}/{repo_name} already exists!")
        repo_data = r.json()
    elif r.status_code == 404:
        print(f"✨ Creating new public repository {user}/{repo_name} on GitHub...")
        payload = {
            'name': repo_name,
            'description': description,
            'private': False,
            'has_issues': True,
            'has_projects': True,
            'has_wiki': True
        }
        create_res = requests.post('https://api.github.com/user/repos', headers=headers, json=payload)
        if create_res.status_code in (200, 201):
            repo_data = create_res.json()
            print(f"✅ Successfully created repository: {repo_data.get('html_url')}")
        else:
            print(f"❌ Failed to create repository: {create_res.status_code} {create_res.text}", file=sys.stderr)
            sys.exit(1)
    else:
        print(f"❌ Unexpected error checking repo: {r.status_code} {r.text}", file=sys.stderr)
        sys.exit(1)

    html_url = repo_data.get('html_url')
    clone_url = f'https://{token}@github.com/{user}/{repo_name}.git'

    # Configure git
    subprocess.run(['git', 'config', 'user.name', user], check=True)
    subprocess.run(['git', 'config', 'user.email', f'{user}@users.noreply.github.com'], check=True)
    subprocess.run(['git', 'add', '.'], check=True)
    subprocess.run(['git', 'commit', '--amend', '-m', 'feat: initial commit for codex-security-linter action'], check=True)
    subprocess.run(['git', 'branch', '-M', 'main'], check=True)

    # Set remote origin
    remotes = subprocess.run(['git', 'remote'], capture_output=True, text=True).stdout.split()
    if 'origin' in remotes:
        subprocess.run(['git', 'remote', 'set-url', 'origin', clone_url], check=True)
    else:
        subprocess.run(['git', 'remote', 'add', 'origin', clone_url], check=True)

    # Push to GitHub
    print(f"🚀 Pushing main branch to {html_url}...")
    push_res = subprocess.run(['git', 'push', '-u', 'origin', 'main', '--force'], capture_output=True, text=True)
    
    # Reset remote to clean URL
    clean_remote_url = f'https://github.com/{user}/{repo_name}.git'
    subprocess.run(['git', 'remote', 'set-url', 'origin', clean_remote_url], check=True)

    if push_res.returncode == 0:
        print(f"🎉 Successfully published to {html_url}!")
    else:
        print(f"❌ Push failed:\n{push_res.stderr}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
