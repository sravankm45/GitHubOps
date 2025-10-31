const axios = require('axios');
const logger = require('./logger');

async function remediateFinding(finding) {
  if (finding.type === 'inactive_collaborator') {
    // Extract owner/repo from TARGET_REPO or from the resource string
    const TARGET_REPO = process.env.TARGET_REPO;
    const [owner, repo] = TARGET_REPO.split('/');
    const username = finding.metadata?.collaborator;

    if (!username) throw new Error('Collaborator username missing');

    logger.info(`Revoking access for inactive collaborator: ${username}`);

    const url = `https://api.github.com/repos/${owner}/${repo}/collaborators/${username}`;
    const headers = {
      Authorization: `token ${process.env.GITHUB_TOKEN}`,
      Accept: 'application/vnd.github.v3+json'
    };

    try {
      const response = await axios.delete(url, { headers });
      if (response.status === 204) {
        logger.info(`Successfully removed ${username} from ${owner}/${repo}`);
        return { message: `Removed inactive collaborator ${username}` };
      } else {
        throw new Error(`Unexpected response: ${response.status}`);
      }
    } catch (err) {
      logger.error(`Failed to remove collaborator: ${err.message}`);
      throw new Error(`GitHub API error: ${err.response?.data?.message || err.message}`);
    }
  }

  // other remediation types can be added here later
  return { message: `No remediation implemented for type ${finding.type}` };
}

module.exports = { remediateFinding };
