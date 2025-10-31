require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const logger = require('./logger');
const { getFindings } = require('./findingsStore');
const { scanRepo } = require('./scanner');
const github = require('./githubClient');
const { remediateFinding } = require('./remediate');

const PORT = process.env.PORT || 3000;
// const TARGET_ORG = process.env.TARGET_ORG;
const TARGET_REPO = process.env.TARGET_REPO;
const SCAN_MAX_REPOS = parseInt(process.env.SCAN_MAX_REPOS || '10');

const app = express();
app.use(bodyParser.json());

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok', ts: new Date().toISOString() });
});

// Fetch stored findings
app.get('/findings', (req, res) => {
  const { type, severity, status } = req.query;
  const filter = {};
  if (type) filter.type = type;
  if (severity) filter.severity = severity;
  if (status) filter.status = status;

  const findings = getFindings(filter);
  res.json({ count: findings.length, findings });
});

// Trigger repo/org rescan
app.post('/rescan', async (req, res) => {
  console.log('in rescan');
  console.log('TARGET_REPO:', TARGET_REPO);
//   console.log('TARGET_ORG:', TARGET_ORG);

  try {
    if (TARGET_REPO) {
      const [owner, repo] = TARGET_REPO.split('/');
      if (!owner || !repo) {
        return res.status(400).json({ error: 'Invalid TARGET_REPO format. Use owner/repo.' });
      }
      await scanRepo(owner, repo);
    // } else if (TARGET_ORG) {
    //   const repos = await github.listOrgRepos(TARGET_ORG, 50, SCAN_MAX_REPOS);
    //   for (const r of repos) {
    //     await scanRepo(r.owner.login, r.name);
    //   }
    } else {
      return res.status(400).json({ error: 'No TARGET_REPO or TARGET_ORG set in .env' });
    }

    res.json({ ok: true, message: 'Rescan complete' });
  } catch (err) {
    logger.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/remediate/:id', async (req, res) => {
  const id = req.params.id;  // extract finding ID from URL
  const f = require('./findingsStore').FINDINGS.find(x => x.id === id); // find the matching record

  console.log("f",f);
  

  if (!f) return res.status(404).json({ error: 'finding not found' }); // no record → 404

  try {
    const result = await remediateFinding(f); // call function to perform the action
    res.json({ ok: true, result }); // success
  } catch (err) {
    logger.error(err);
    res.status(500).json({ ok: false, error: err.message }); // handle failure
  }
});


app.listen(PORT, () => {
  logger.info(`Server listening on port ${PORT}`);
});
