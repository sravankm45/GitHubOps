const github = require('./githubClient');
const { shannonEntropy } = require('./utils');
const { addFinding } = require('./findingsStore');
const logger = require('./logger');

const SECRET_REGEXPS = [
    /(api[_-]?key)\s*[:=]\s*['"]?([A-Za-z0-9\-_]{20,})['"]?/gi,
    /(aws_access_key_id|aws_secret_access_key)\s*[:=]\s*['"]?([A-Za-z0-9\/+=]{16,40})['"]?/gi,
    /(-----BEGIN RSA PRIVATE KEY-----)/g
];

const SENSITIVE_DIRS = ['.github', 'infra', 'deploy', 'secrets', 'config'];

async function scanRepo(owner, repoName) {
    console.log("owner, repoName", owner, repoName);

    try {
        const repo = await github.getRepo(owner, repoName);
        logger.info(`Scanning repo: ${owner}/${repoName}`);

        // Repo visibility
        if (!repo.private) addFinding({ type: 'repo_visibility', severity: 'high', resource: `${owner}/${repoName}`, description: 'Repository is public.' });

        // Branch protection
        const defaultBranch = repo.default_branch || 'main';
        const bp = await github.getBranchProtection(owner, repoName, defaultBranch);
        if (!bp) addFinding({ type: 'branch_protection_missing', severity: 'high', resource: `${owner}/${repoName}@${defaultBranch}`, description: `Branch protection missing on ${defaultBranch}.` });

        // Commit messages scan (recent)
        const commits = await github.listCommits(owner, repoName, { per_page: 50 });
        for (const c of commits) {
            const msg = c.commit && c.commit.message ? c.commit.message : '';
            for (const r of SECRET_REGEXPS) {
                r.lastIndex = 0;
                const m = r.exec(msg);
                if (m) addFinding({ type: 'secret_in_commit_message', severity: 'high', resource: `${owner}/${repoName} commit ${c.sha}`, description: `Secret-like string in commit message: ${m[0].slice(0, 120)}` });
            }
        }

        // Check some common sensitive file paths
        const commonPaths = ['.env', '.env.local', 'secrets.json', 'id_rsa', 'config.env'];
        for (const path of commonPaths) {
            const contentMeta = await github.getFileContent(owner, repoName, path, defaultBranch).catch(() => null);
            if (contentMeta && contentMeta.content) {
                const raw = Buffer.from(contentMeta.content, 'base64').toString('utf8');
                secretScanString(raw, owner, repoName, `${path}@${defaultBranch}`);
            }
        }

        // Collaborators inactivity (simple heuristic)
        const collaborators = await github.listCollaborators(owner, repoName).catch(() => []);
        for (const coll of collaborators) {
            const commitsByUser = await github.listCommits(owner, repoName, { per_page: 50, author: coll.login }).catch(() => []);
            let lastActivity = commitsByUser && commitsByUser.length ? commitsByUser[0].commit.author.date : null;
            if (!lastActivity) {
                addFinding({ type: 'inactive_collaborator', severity: 'medium', resource: `${owner}/${repoName} collaborator:${coll.login}`, description: `Collaborator ${coll.login} has no recent commits.`, metadata: { collaborator: coll.login } });
            } else {
                const days = (Date.now() - new Date(lastActivity).getTime()) / (1000 * 60 * 60 * 24);
                if (days > 90) addFinding({ type: 'inactive_collaborator', severity: 'low', resource: `${owner}/${repoName} collaborator:${coll.login}`, description: `Last commit ${lastActivity}`, metadata: { collaborator: coll.login, lastActivity } });
            }
        }

        // Pull requests checks
        // Pull requests checks
        const prs = await github.listPulls(owner, repoName, { state: 'open', per_page: 50 });

        for (const pr of prs) {
            const files = await github.getPullFiles(owner, repoName, pr.number).catch(() => []);
            const commitsInPR = await github.listPullCommits(owner, repoName, pr.number).catch(() => []);

            let totalChanges = 0;
            let changesSensitive = false;
            let unsignedCommits = false;

            for (const f of files) {
                totalChanges += f.changes || 0;
                for (const sd of SENSITIVE_DIRS) {
                    if (f.filename.startsWith(sd + '/')) changesSensitive = true;
                }
            }

            // Detect unsigned commits in the PR
            for (const commit of commitsInPR) {
                const verified = commit.commit?.verification?.verified;
                if (!verified) {
                    unsignedCommits = true;
                    break;
                }
            }

            const noReviewers = (pr.requested_reviewers || []).length === 0;

            // Determine severity
            const riskyConditions = [];
            if (totalChanges > 200) riskyConditions.push('large diff');
            if (changesSensitive) riskyConditions.push('changes in sensitive dirs');
            if (noReviewers) riskyConditions.push('no reviewers');
            if (unsignedCommits) riskyConditions.push('unsigned commits');

            if (riskyConditions.length > 0) {
                const severity =
                    totalChanges > 500 || changesSensitive || unsignedCommits ? 'high' : 'medium';

                addFinding({
                    type: 'risky_pr',
                    severity,
                    resource: `${owner}/${repoName} PR#${pr.number}`,
                    description: `PR "${pr.title}" has ${riskyConditions.join(', ')}`,
                    metadata: {
                        pr_number: pr.number,
                        totalChanges,
                        noReviewers,
                        changesSensitive,
                        unsignedCommits,
                    },
                });
            }
        }


    } catch (err) {
        logger.error(`scanRepo error for ${owner}/${repoName}: ${err.message}`);
    }
}

function secretScanString(s, owner, repoName, resourcePath) {
    for (const r of SECRET_REGEXPS) { r.lastIndex = 0; const m = r.exec(s); if (m) addFinding({ type: 'secret_in_file', severity: 'high', resource: `${owner}/${repoName}:${resourcePath}`, description: `Secret-like string: ${m[0].slice(0, 120)}` }); }
    const tokens = s.split(/\s+/).filter(w => w.length >= 20 && w.length <= 200);
    for (const t of tokens) {
        const ent = shannonEntropy(t);
        if (ent > 4.0) addFinding({ type: 'high_entropy_string', severity: 'medium', resource: `${owner}/${repoName}:${resourcePath}`, description: `High-entropy string length=${t.length} ent=${ent.toFixed(2)}` });
    }
}

module.exports = { scanRepo, secretScanString };
