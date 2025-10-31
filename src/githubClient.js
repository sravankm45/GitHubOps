const axios = require('axios');
const logger = require('./logger');
const TOKEN = process.env.GITHUB_TOKEN;
if (!TOKEN) {
  logger.error('GITHUB_TOKEN not set in env'); process.exit(1);
}
const client = axios.create({
  baseURL: 'https://api.github.com',
  headers: {
    Authorization: `token ${TOKEN}`,
    Accept: 'application/vnd.github+json',
    'User-Agent': 'gitsafeops'
  },
  timeout: 20000
});

async function listOrgRepos(org, per_page = 50, max=50) {
  let page = 1, all = [];
  while (all.length < max) {
    const res = await client.get(`/orgs/${org}/repos`, { params: { per_page, page }});
    if (!res.data || res.data.length === 0) break;
    all = all.concat(res.data);
    page++;
    if (res.data.length < per_page) break;
  }
  return all.slice(0, max);
}

async function getRepo(owner, repo) { const res = await client.get(`/repos/${owner}/${repo}`); return res.data; }
async function listCollaborators(owner, repo) { const res = await client.get(`/repos/${owner}/${repo}/collaborators`); return res.data; }
async function listCommits(owner, repo, params={per_page: 50}) { const res = await client.get(`/repos/${owner}/${repo}/commits`, { params }); return res.data; }
async function getBranchProtection(owner, repo, branch) {
  try {
    const res = await client.get(`/repos/${owner}/${repo}/branches/${encodeURIComponent(branch)}/protection`, {
      headers: { Accept: 'application/vnd.github.luke-cage-preview+json' }
    });
    return res.data;
  } catch (err) {
    if (err.response && err.response.status === 404) return null;
    throw err;
  }
}
async function listPulls(owner, repo, params={state: 'open', per_page: 50}) { const res = await client.get(`/repos/${owner}/${repo}/pulls`, { params }); return res.data; }
async function getPullFiles(owner, repo, pull_number) { const res = await client.get(`/repos/${owner}/${repo}/pulls/${pull_number}/files`); return res.data; }
async function getFileContent(owner, repo, path, ref) {
  try {
    const res = await client.get(`/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`, { params: { ref }});
    return res.data;
  } catch (err) {
    if (err.response && err.response.status === 404) return null;
    throw err;
  }
}
async function removeCollaborator(owner, repo, username) {
  const res = await client.delete(`/repos/${owner}/${repo}/collaborators/${username}`);
  return res.status === 204;
}
async function createIssue(owner, repo, title, body) {
  const res = await client.post(`/repos/${owner}/${repo}/issues`, { title, body });
  return res.data;
}

module.exports = { client, listOrgRepos, getRepo, listCollaborators, listCommits, getBranchProtection, listPulls, getPullFiles, getFileContent, removeCollaborator, createIssue };
