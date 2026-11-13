// Resolve the GitHub Pages project subpath from the current repository identity.
// EXPLOIT_ATLAS_PAGES_SITE permits an explicit, safe migration rehearsal.
const supported = new Set(['patchline', 'exploit-atlas']);

export function pagesBase(env = process.env) {
  const override = env.EXPLOIT_ATLAS_PAGES_SITE;
  if (override !== undefined && override !== '') {
    if (!supported.has(override)) {
      throw Error('Unsupported explicit GitHub Pages site identity');
    }
    return `/${override}/`;
  }

  const repository = env.GITHUB_REPOSITORY;
  if (repository !== undefined && repository !== '') {
    const parts = repository.split('/');
    if (parts.length !== 2 || !parts[0] || !supported.has(parts[1])) {
      throw Error('Unexpected GitHub Pages repository identity');
    }
    return `/${parts[1]}/`;
  }

  // On a local workstation outside GitHub Actions, retain the existing
  // deployment subpath until the repository is renamed.
  return '/patchline/';
}
